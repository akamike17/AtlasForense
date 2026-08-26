using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using AtlasForense.Models;

namespace AtlasForense.Services;

public sealed partial class ContentTransformationService : IContentTransformationService
{
    private const int MaxInputBytes = 1_048_576;
    private const int MaxOutputBytes = 4_194_304;
    private const string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private const string Base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    public TransformationResult Transform(TransformationInput input)
    {
        var inputBytes = Encoding.UTF8.GetBytes(input.Input ?? string.Empty);
        var inputHash = Hash(inputBytes);
        if (inputBytes.Length > MaxInputBytes) return Failure("La entrada excede 1 MiB.", inputHash, inputBytes.Length, input);
        try
        {
            var output = Apply(input);
            var outputBytes = Encoding.UTF8.GetBytes(output);
            if (outputBytes.Length > MaxOutputBytes) return Failure("La salida excede el límite seguro de 4 MiB.", inputHash, inputBytes.Length, input);
            return new(true, output, string.Empty, inputHash, Hash(outputBytes), inputBytes.Length, outputBytes.Length, Recipe(input));
        }
        catch (Exception exception) when (exception is FormatException or ArgumentException or OverflowException or DecoderFallbackException)
        {
            return Failure($"Entrada inválida para {input.Algorithm}: {exception.Message}", inputHash, inputBytes.Length, input);
        }
    }

    public IReadOnlyList<DecodingLayer> DetectAndDecode(string input, int maxDepth = 6)
    {
        maxDepth = Math.Clamp(maxDepth, 1, 12);
        var layers = new List<DecodingLayer>();
        var current = input;
        var seen = new HashSet<string>(StringComparer.Ordinal) { Hash(Encoding.UTF8.GetBytes(input)) };
        for (var depth = 1; depth <= maxDepth; depth++)
        {
            var candidates = CandidateDecoders(current)
                .Select(x => (x.Name, Result: Transform(new TransformationInput { Input = current, Direction = TransformationDirection.Decode, Algorithm = x.Algorithm, Parameter = x.Parameter })))
                .Where(x => x.Result.Success && x.Result.Output != current)
                .Select(x => (x.Name, x.Result, Score: TextScore(x.Result.Output)))
                .Where(x => x.Score >= 0.55)
                .OrderByDescending(x => x.Score)
                .ThenBy(x => x.Result.OutputBytes)
                .ToList();
            var best = candidates.FirstOrDefault(x => !seen.Contains(x.Result.OutputSha256));
            if (best.Result is null) break;
            seen.Add(best.Result.OutputSha256);
            layers.Add(new DecodingLayer(depth, best.Name, best.Result.InputSha256, best.Result.OutputSha256, best.Result.Output, best.Score));
            current = best.Result.Output;
        }
        return layers;
    }

    private static string Apply(TransformationInput input)
    {
        var encode = input.Direction == TransformationDirection.Encode;
        var bytes = Encoding.UTF8.GetBytes(input.Input);
        return input.Algorithm switch
        {
            TransformationAlgorithm.Base2 => encode ? string.Concat(bytes.Select(x => Convert.ToString(x, 2).PadLeft(8, '0'))) : Encoding.UTF8.GetString(ParseFixedBase(input.Input, 2, 8)),
            TransformationAlgorithm.Base8 => encode ? string.Join(' ', bytes.Select(x => Convert.ToString(x, 8).PadLeft(3, '0'))) : Encoding.UTF8.GetString(ParseDelimitedBase(input.Input, 8)),
            TransformationAlgorithm.Base10 => encode ? string.Join(' ', bytes) : Encoding.UTF8.GetString(ParseDelimitedBase(input.Input, 10)),
            TransformationAlgorithm.Base16 => encode ? Convert.ToHexString(bytes).ToLowerInvariant() : Encoding.UTF8.GetString(Convert.FromHexString(RemoveWhitespace(input.Input))),
            TransformationAlgorithm.Base32 => encode ? Base32Encode(bytes) : Encoding.UTF8.GetString(Base32Decode(input.Input)),
            TransformationAlgorithm.Base58 => encode ? Base58Encode(bytes) : Encoding.UTF8.GetString(Base58Decode(input.Input)),
            TransformationAlgorithm.Base64 => encode ? Convert.ToBase64String(bytes) : Encoding.UTF8.GetString(Convert.FromBase64String(RemoveWhitespace(input.Input))),
            TransformationAlgorithm.Base64Url => encode ? Base64UrlEncode(bytes) : Encoding.UTF8.GetString(Base64UrlDecode(input.Input)),
            TransformationAlgorithm.Ascii85 => encode ? Ascii85Encode(bytes) : Encoding.UTF8.GetString(Ascii85Decode(input.Input)),
            TransformationAlgorithm.RotAlpha => RotateAlpha(input.Input, SignedParameter(input.Parameter, 13) * (encode ? 1 : -1)),
            TransformationAlgorithm.Rot47 => Rot47(input.Input),
            TransformationAlgorithm.RotateBits => encode ? Convert.ToBase64String(RotateBits(bytes, SignedParameter(input.Parameter, 1), true)) : Encoding.UTF8.GetString(RotateBits(Convert.FromBase64String(RemoveWhitespace(input.Input)), SignedParameter(input.Parameter, 1), false)),
            TransformationAlgorithm.Xor => encode ? Convert.ToBase64String(Xor(bytes, ParseKey(input.Parameter))) : Encoding.UTF8.GetString(Xor(Convert.FromBase64String(RemoveWhitespace(input.Input)), ParseKey(input.Parameter))),
            TransformationAlgorithm.Reverse => new string(input.Input.EnumerateRunes().Reverse().SelectMany(x => x.ToString()).ToArray()),
            TransformationAlgorithm.Url => encode ? Uri.EscapeDataString(input.Input) : Uri.UnescapeDataString(input.Input),
            TransformationAlgorithm.Html => encode ? WebUtility.HtmlEncode(input.Input) : WebUtility.HtmlDecode(input.Input),
            TransformationAlgorithm.UnicodeEscape => encode ? string.Concat(input.Input.EnumerateRunes().Select(r => r.Value <= 0xffff ? $"\\u{r.Value:x4}" : $"\\U{r.Value:x8}")) : DecodeUnicodeEscapes(input.Input),
            _ => throw new ArgumentOutOfRangeException(nameof(input.Algorithm))
        };
    }

    private static IEnumerable<(string Name, TransformationAlgorithm Algorithm, string Parameter)> CandidateDecoders(string value)
    {
        var compact = RemoveWhitespace(value);
        if (compact.Length >= 8 && compact.Length % 8 == 0 && BinaryRegex().IsMatch(compact)) yield return ("Base2", TransformationAlgorithm.Base2, "");
        if (compact.Length >= 4 && compact.Length % 2 == 0 && HexRegex().IsMatch(compact)) yield return ("Base16", TransformationAlgorithm.Base16, "");
        if (compact.Length >= 8 && Base32Regex().IsMatch(compact)) yield return ("Base32", TransformationAlgorithm.Base32, "");
        if (compact.Length >= 4 && Base64Regex().IsMatch(compact)) yield return ("Base64", TransformationAlgorithm.Base64, "");
        if (compact.Length >= 4 && Base64UrlRegex().IsMatch(compact) && (compact.Contains('-') || compact.Contains('_'))) yield return ("Base64Url", TransformationAlgorithm.Base64Url, "");
        if (value.Contains('%')) yield return ("URL", TransformationAlgorithm.Url, "");
        if (value.Contains('&') && value.Contains(';')) yield return ("HTML", TransformationAlgorithm.Html, "");
        if (value.Contains("\\u", StringComparison.OrdinalIgnoreCase) || value.Contains("\\U", StringComparison.Ordinal)) yield return ("UnicodeEscape", TransformationAlgorithm.UnicodeEscape, "");
    }

    private static byte[] ParseFixedBase(string value, int radix, int width)
    {
        var compact = RemoveWhitespace(value);
        if (compact.Length == 0 || compact.Length % width != 0) throw new FormatException($"Se requieren grupos de {width} dígitos.");
        return Enumerable.Range(0, compact.Length / width).Select(i => checked((byte)Convert.ToInt32(compact.Substring(i * width, width), radix))).ToArray();
    }

    private static byte[] ParseDelimitedBase(string value, int radix) => value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).Select(x => checked((byte)Convert.ToInt32(x, radix))).ToArray();
    private static string RemoveWhitespace(string value) => WhitespaceRegex().Replace(value, string.Empty);
    private static int SignedParameter(string value, int fallback) => string.IsNullOrWhiteSpace(value) ? fallback : int.Parse(value, CultureInfo.InvariantCulture);
    private static byte[] ParseKey(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) throw new ArgumentException("XOR requiere una clave UTF-8.");
        return Encoding.UTF8.GetBytes(value);
    }
    private static byte[] Xor(byte[] value, byte[] key) => value.Select((x, i) => (byte)(x ^ key[i % key.Length])).ToArray();
    private static byte[] RotateBits(byte[] value, int count, bool left)
    {
        count = ((count % 8) + 8) % 8;
        if (!left) count = (8 - count) % 8;
        return value.Select(x => (byte)((x << count) | (x >> (8 - count)))).ToArray();
    }
    private static string RotateAlpha(string value, int shift)
    {
        shift = ((shift % 26) + 26) % 26;
        return string.Concat(value.Select(c => c is >= 'a' and <= 'z' ? (char)('a' + (c - 'a' + shift) % 26) : c is >= 'A' and <= 'Z' ? (char)('A' + (c - 'A' + shift) % 26) : c));
    }
    private static string Rot47(string value) => string.Concat(value.Select(c => c is >= '!' and <= '~' ? (char)('!' + (c - '!' + 47) % 94) : c));
    private static string DecodeUnicodeEscapes(string value) => UnicodeRegex().Replace(value, match => char.ConvertFromUtf32(Convert.ToInt32(match.Groups[1].Success ? match.Groups[1].Value : match.Groups[2].Value, 16)));

    private static string Base32Encode(byte[] data)
    {
        if (data.Length == 0) return string.Empty;
        var output = new StringBuilder((data.Length + 4) / 5 * 8); var buffer = (int)data[0]; var next = 1; var bits = 8;
        while (bits > 0 || next < data.Length) { if (bits < 5) { if (next < data.Length) { buffer = (buffer << 8) | data[next++]; bits += 8; } else { buffer <<= 5 - bits; bits = 5; } } output.Append(Base32Alphabet[(buffer >> (bits - 5)) & 31]); bits -= 5; }
        while (output.Length % 8 != 0) output.Append('='); return output.ToString();
    }
    private static byte[] Base32Decode(string value)
    {
        var clean = RemoveWhitespace(value).TrimEnd('=').ToUpperInvariant(); var output = new List<byte>(); var buffer = 0; var bits = 0;
        foreach (var c in clean) { var index = Base32Alphabet.IndexOf(c); if (index < 0) throw new FormatException("Carácter Base32 inválido."); buffer = (buffer << 5) | index; bits += 5; if (bits >= 8) { output.Add((byte)(buffer >> (bits - 8))); bits -= 8; buffer &= (1 << bits) - 1; } } return output.ToArray();
    }
    private static string Base58Encode(byte[] data) => BaseXEncode(data, Base58Alphabet);
    private static byte[] Base58Decode(string value) => BaseXDecode(RemoveWhitespace(value), Base58Alphabet);
    private static string BaseXEncode(byte[] data, string alphabet)
    {
        if (data.Length == 0) return string.Empty; var digits = new List<int> { 0 };
        foreach (var b in data) { var carry = (int)b; for (var i = 0; i < digits.Count; i++) { carry += digits[i] << 8; digits[i] = carry % alphabet.Length; carry /= alphabet.Length; } while (carry > 0) { digits.Add(carry % alphabet.Length); carry /= alphabet.Length; } }
        var zeros = data.TakeWhile(x => x == 0).Count(); return new string(alphabet[0], zeros) + string.Concat(digits.AsEnumerable().Reverse().SkipWhile((_, i) => i == 0 && digits[^1] == 0 && zeros > 0).Select(x => alphabet[x]));
    }
    private static byte[] BaseXDecode(string value, string alphabet)
    {
        if (value.Length == 0) return []; var bytes = new List<int> { 0 };
        foreach (var c in value) { var digit = alphabet.IndexOf(c); if (digit < 0) throw new FormatException("Carácter Base58 inválido."); var carry = digit; for (var i = 0; i < bytes.Count; i++) { carry += bytes[i] * alphabet.Length; bytes[i] = carry & 255; carry >>= 8; } while (carry > 0) { bytes.Add(carry & 255); carry >>= 8; } }
        var zeros = value.TakeWhile(x => x == alphabet[0]).Count(); return Enumerable.Repeat((byte)0, zeros).Concat(bytes.AsEnumerable().Reverse().SkipWhile((x, i) => i == 0 && x == 0 && zeros > 0).Select(x => (byte)x)).ToArray();
    }
    private static string Base64UrlEncode(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static byte[] Base64UrlDecode(string value) { var clean = RemoveWhitespace(value).Replace('-', '+').Replace('_', '/'); clean = clean.PadRight(clean.Length + (4 - clean.Length % 4) % 4, '='); return Convert.FromBase64String(clean); }
    private static string Ascii85Encode(byte[] data)
    {
        var result = new StringBuilder("<~");
        for (var i = 0; i < data.Length; i += 4) { var count = Math.Min(4, data.Length - i); uint tuple = 0; for (var j = 0; j < 4; j++) tuple = (tuple << 8) | (j < count ? data[i + j] : 0u); if (tuple == 0 && count == 4) { result.Append('z'); continue; } var block = new char[5]; for (var j = 4; j >= 0; j--) { block[j] = (char)(tuple % 85 + 33); tuple /= 85; } result.Append(block, 0, count + 1); }
        return result.Append("~>").ToString();
    }
    private static byte[] Ascii85Decode(string value)
    {
        var clean = RemoveWhitespace(value); if (clean.StartsWith("<~")) clean = clean[2..]; if (clean.EndsWith("~>")) clean = clean[..^2]; var output = new List<byte>(); var group = new List<int>(5);
        foreach (var c in clean) { if (c == 'z') { if (group.Count != 0) throw new FormatException("'z' fuera de grupo."); output.AddRange(new byte[4]); continue; } if (c is < '!' or > 'u') throw new FormatException("Carácter Ascii85 inválido."); group.Add(c - 33); if (group.Count == 5) { AppendAscii85(output, group, 4); group.Clear(); } }
        if (group.Count == 1) throw new FormatException("Grupo Ascii85 incompleto."); if (group.Count > 1) { var bytes = group.Count - 1; while (group.Count < 5) group.Add(84); AppendAscii85(output, group, bytes); } return output.ToArray();
    }
    private static void AppendAscii85(List<byte> output, List<int> group, int count) { ulong value = 0; foreach (var digit in group) value = value * 85 + (uint)digit; if (value > uint.MaxValue) throw new FormatException("Grupo Ascii85 fuera de rango."); for (var i = 3; i >= 4 - count; i--) output.Add((byte)(value >> (i * 8))); }

    private static double TextScore(string value)
    {
        if (value.Length == 0) return 0; var printable = value.Count(c => !char.IsControl(c) || c is '\r' or '\n' or '\t'); var ratio = (double)printable / value.Length; var bonus = CommonTextRegex().IsMatch(value) ? 0.12 : 0; return Math.Min(1, ratio + bonus);
    }
    private static string Hash(byte[] value) => Convert.ToHexString(SHA256.HashData(value)).ToLowerInvariant();
    private static string Recipe(TransformationInput input) => $"{input.Direction}:{input.Algorithm}{(string.IsNullOrWhiteSpace(input.Parameter) ? string.Empty : $"({input.Parameter})")}";
    private static TransformationResult Failure(string error, string inputHash, int inputBytes, TransformationInput input) => new(false, string.Empty, error, inputHash, string.Empty, inputBytes, 0, Recipe(input));

    [GeneratedRegex(@"\s+")] private static partial Regex WhitespaceRegex();
    [GeneratedRegex(@"^[01]+$")] private static partial Regex BinaryRegex();
    [GeneratedRegex(@"^[0-9a-fA-F]+$")] private static partial Regex HexRegex();
    [GeneratedRegex(@"^[A-Z2-7]+=*$", RegexOptions.IgnoreCase)] private static partial Regex Base32Regex();
    [GeneratedRegex(@"^[A-Za-z0-9+/]+={0,2}$")] private static partial Regex Base64Regex();
    [GeneratedRegex(@"^[A-Za-z0-9_-]+={0,2}$")] private static partial Regex Base64UrlRegex();
    [GeneratedRegex(@"\\(?:u([0-9a-fA-F]{4})|U([0-9a-fA-F]{8}))")] private static partial Regex UnicodeRegex();
    [GeneratedRegex(@"(?:https?://|function\s|powershell|cmd\.exe|SELECT\s|\{\s*[A-Za-z_])", RegexOptions.IgnoreCase)] private static partial Regex CommonTextRegex();
}

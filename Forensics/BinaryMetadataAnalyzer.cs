using System.Text;
using System.Text.RegularExpressions;
using AtlasForense.Models;

namespace AtlasForense.Forensics;

public sealed partial class BinaryMetadataAnalyzer : IForensicAnalyzer
{
    private const int MaxInspectionBytes = 16 * 1024 * 1024;
    private const int MaxStrings = 5_000;
    public string Id => "binary-metadata-strings";
    public string Version => "1.0.0";
    public bool CanAnalyze(EvidenceItem evidence) => true;

    public async Task<AnalyzerOutput> AnalyzeAsync(AnalyzerContext context)
    {
        var output = new AnalyzerOutput();
        var data = await ReadBounded(context.FilePath, context.CancellationToken);
        var fileType = DetectFileType(data);
        var entropy = ShannonEntropy(data);
        Add(output, context, ArtifactKind.FileType, "Tipo por firma", fileType, "Detectado por bytes mágicos, no por extensión", ConfidenceLevel.Observed);
        Add(output, context, ArtifactKind.Entropy, "Entropía Shannon", entropy.ToString("F4", System.Globalization.CultureInfo.InvariantCulture), $"Calculada sobre {data.Length} bytes", ConfidenceLevel.Observed);

        if (entropy >= 7.2)
            Add(output, context, ArtifactKind.Capability, "Indicador", "Alta entropía / posible compresión, cifrado o empaquetado", "La entropía por sí sola no confirma intención maliciosa", ConfidenceLevel.Inferred);

        foreach (var value in ExtractStrings(data).Distinct(StringComparer.Ordinal).Take(MaxStrings))
        {
            if (value.Length > 2_000) continue;
            Add(output, context, ArtifactKind.String, "Cadena", value, "Cadena imprimible extraída sin ejecutar la muestra", ConfidenceLevel.Observed);
            foreach (Match match in UrlRegex().Matches(value)) AddIndicator(output, context, ArtifactKind.Url, IndicatorType.Url, match.Value.TrimEnd('.', ',', ';', ')', ']', '}', '\'', '"'));
            foreach (Match match in IpRegex().Matches(value)) AddIndicator(output, context, ArtifactKind.IpAddress, IndicatorType.IpAddress, match.Value);
        }

        output.Summary = $"Metadatos binarios: {fileType}; entropía {entropy:F4}; {output.Artifacts.Count(x => x.Kind == ArtifactKind.String)} cadenas; muestra no ejecutada y red no utilizada.";
        return output;
    }

    private static async Task<byte[]> ReadBounded(string path, CancellationToken token)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, true);
        var length = (int)Math.Min(stream.Length, MaxInspectionBytes); var data = new byte[length]; var offset = 0;
        while (offset < length) { var read = await stream.ReadAsync(data.AsMemory(offset, length - offset), token); if (read == 0) break; offset += read; }
        return offset == length ? data : data[..offset];
    }

    private static string DetectFileType(ReadOnlySpan<byte> data)
    {
        if (Starts(data, 0x4d, 0x5a)) return "Windows PE / DOS executable";
        if (Starts(data, 0x7f, 0x45, 0x4c, 0x46)) return "ELF executable";
        if (Starts(data, 0x50, 0x4b, 0x03, 0x04)) return "ZIP / Office Open XML / JAR";
        if (Starts(data, 0x1f, 0x8b)) return "GZIP";
        if (Starts(data, 0x25, 0x50, 0x44, 0x46, 0x2d)) return "PDF";
        if (Starts(data, 0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a)) return "PNG image";
        if (Starts(data, 0xff, 0xd8, 0xff)) return "JPEG image";
        if (Starts(data, 0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x20, 0x33, 0x00)) return "SQLite 3 database";
        if (Starts(data, 0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1)) return "OLE Compound Document";
        return LooksTextual(data) ? "Text / script data" : "Unknown binary data";
    }

    private static bool Starts(ReadOnlySpan<byte> data, params byte[] signature) => data.Length >= signature.Length && data[..signature.Length].SequenceEqual(signature);
    private static bool LooksTextual(ReadOnlySpan<byte> data)
    {
        var length = Math.Min(data.Length, 4096); if (length == 0) return false; var printable = 0;
        for (var i = 0; i < length; i++) if (data[i] is 9 or 10 or 13 || data[i] is >= 32 and <= 126) printable++;
        return printable >= length * 0.85;
    }
    private static double ShannonEntropy(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0) return 0; Span<int> counts = stackalloc int[256]; foreach (var value in data) counts[value]++;
        double entropy = 0; foreach (var count in counts) if (count > 0) { var p = (double)count / data.Length; entropy -= p * Math.Log2(p); } return entropy;
    }

    private static IEnumerable<string> ExtractStrings(byte[] data)
    {
        foreach (Match match in AsciiStringRegex().Matches(Encoding.Latin1.GetString(data))) yield return match.Value;
        var unicode = Encoding.Unicode.GetString(data); foreach (Match match in UnicodeStringRegex().Matches(unicode)) yield return match.Value;
    }
    private static void Add(AnalyzerOutput output, AnalyzerContext context, ArtifactKind kind, string name, string value, string detail, ConfidenceLevel confidence) => output.Artifacts.Add(new AnalysisArtifact { EvidenceId = context.Evidence.Id, AnalysisRunId = context.AnalysisRunId, Kind = kind, Name = name, Value = value, Context = detail, Confidence = confidence });
    private static void AddIndicator(AnalyzerOutput output, AnalyzerContext context, ArtifactKind kind, IndicatorType type, string value)
    {
        if (output.Indicators.Any(x => x.Type == type && x.Value.Equals(value, StringComparison.OrdinalIgnoreCase))) return;
        Add(output, context, kind, kind.ToString(), value, "Extraído de cadena binaria", ConfidenceLevel.Observed);
        output.Indicators.Add(new CaseIndicator { Type = type, Value = value, NormalizedValue = value.ToLowerInvariant(), Description = "Extraído de cadena binaria", Confidence = ConfidenceLevel.Observed, EvidenceIds = [context.Evidence.Id] });
    }

    [GeneratedRegex(@"[\x20-\x7e]{4,}", RegexOptions.CultureInvariant)] private static partial Regex AsciiStringRegex();
    [GeneratedRegex(@"[\x20-\x7e]{4,}", RegexOptions.CultureInvariant)] private static partial Regex UnicodeStringRegex();
    [GeneratedRegex(@"https?://[^\s<>""']+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)] private static partial Regex UrlRegex();
    [GeneratedRegex(@"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])", RegexOptions.CultureInvariant)] private static partial Regex IpRegex();
}

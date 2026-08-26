using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using AtlasForense.Models;
using AtlasForense.Services;

namespace AtlasForense.Forensics;

public sealed partial class StaticTextAnalyzer : IForensicAnalyzer
{
    private const int MaxCharacters = 12_000_000;
    private const int MaxValuesPerKind = 2_000;
    public string Id => "static-text-ioc";
    public string Version => "1.0.0";
    private readonly IContentTransformationService _transformations;

    public StaticTextAnalyzer(IContentTransformationService? transformations = null) => _transformations = transformations ?? new ContentTransformationService();

    public bool CanAnalyze(EvidenceItem evidence)
    {
        var extension = Path.GetExtension(evidence.OriginalFileName).ToLowerInvariant();
        return extension is ".txt" or ".log" or ".md" or ".json" or ".xml" or ".csv" or ".js" or ".mjs" or ".ts" or ".html" or ".htm" or ".php" or ".ps1" or ".cmd" or ".bat" or ".py" or ".ini" or ".conf" or ".yaml" or ".yml";
    }

    public async Task<AnalyzerOutput> AnalyzeAsync(AnalyzerContext context)
    {
        var output = new AnalyzerOutput();
        var text = await ReadBoundedText(context.FilePath, context.CancellationToken);
        var runId = context.AnalysisRunId;

        AddMatches(output, context.Evidence.Id, runId, ArtifactKind.Url, IndicatorType.Url, UrlRegex(), text, value => value.TrimEnd('.', ',', ';', ')', ']', '}', '\'', '"'));
        AddMatches(output, context.Evidence.Id, runId, ArtifactKind.Email, IndicatorType.Email, EmailRegex(), text, value => value.ToLowerInvariant());
        AddMatches(output, context.Evidence.Id, runId, ArtifactKind.IpAddress, IndicatorType.IpAddress, IpRegex(), text, NormalizeIp);
        AddMatches(output, context.Evidence.Id, runId, ArtifactKind.FileHash, IndicatorType.Hash, HashRegex(), text, value => value.ToLowerInvariant());
        DecodeEmbeddedLayers(output, context.Evidence.Id, runId, text);

        foreach (var url in output.Artifacts.Where(x => x.Kind == ArtifactKind.Url).ToList())
        {
            if (!Uri.TryCreate(url.Value, UriKind.Absolute, out var uri) || string.IsNullOrWhiteSpace(uri.Host)) continue;
            AddUnique(output, context.Evidence.Id, runId, ArtifactKind.Domain, IndicatorType.Domain, uri.Host.ToLowerInvariant(), $"Derivado de {url.Value}");
            AddUnique(output, context.Evidence.Id, runId, ArtifactKind.NetworkEndpoint, IndicatorType.Url, $"{uri.Scheme}://{uri.Authority}{uri.AbsolutePath}", "Endpoint observado en contenido estático");
        }

        if (IsScript(context.Evidence.OriginalFileName))
        {
            AddScriptFunctions(output, context.Evidence.Id, runId, text);
            AddCapabilities(output, context.Evidence.Id, runId, text);
        }

        output.Summary = $"Análisis estático: {output.Artifacts.Count} artefactos y {output.Indicators.Count} indicadores extraídos; muestra no ejecutada y red no utilizada.";
        return output;
    }

    private void DecodeEmbeddedLayers(AnalyzerOutput output, Guid evidenceId, Guid runId, string text)
    {
        foreach (Match match in EncodedTokenRegex().Matches(text).Cast<Match>().Take(200))
        {
            var layers = _transformations.DetectAndDecode(match.Value, 4);
            foreach (var layer in layers)
            {
                if (output.Artifacts.Any(x => x.Kind == ArtifactKind.DecodedContent && x.Value == layer.Output)) continue;
                output.Artifacts.Add(new AnalysisArtifact
                {
                    EvidenceId = evidenceId, AnalysisRunId = runId, Kind = ArtifactKind.DecodedContent,
                    Name = $"Capa {layer.Depth}: {layer.Algorithm}", Value = layer.Output,
                    Context = $"Entrada {layer.InputSha256}; salida {layer.OutputSha256}; legibilidad {layer.PrintableRatio:P0}",
                    Offset = match.Index, Confidence = ConfidenceLevel.Observed
                });
                AddMatches(output, evidenceId, runId, ArtifactKind.Url, IndicatorType.Url, UrlRegex(), layer.Output, value => value.TrimEnd('.', ',', ';', ')', ']', '}', '\'', '"'));
                AddMatches(output, evidenceId, runId, ArtifactKind.Email, IndicatorType.Email, EmailRegex(), layer.Output, value => value.ToLowerInvariant());
                AddMatches(output, evidenceId, runId, ArtifactKind.IpAddress, IndicatorType.IpAddress, IpRegex(), layer.Output, NormalizeIp);
            }
        }
    }

    private static async Task<string> ReadBoundedText(string path, CancellationToken token)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, true);
        using var reader = new StreamReader(stream, Encoding.UTF8, true, 81920, leaveOpen: false);
        var buffer = new char[81920];
        var builder = new StringBuilder((int)Math.Min(stream.Length, MaxCharacters));
        while (builder.Length < MaxCharacters)
        {
            var read = await reader.ReadAsync(buffer.AsMemory(0, Math.Min(buffer.Length, MaxCharacters - builder.Length)), token);
            if (read == 0) break;
            builder.Append(buffer, 0, read);
        }
        return builder.ToString();
    }

    private static void AddMatches(AnalyzerOutput output, Guid evidenceId, Guid runId, ArtifactKind kind, IndicatorType indicatorType, Regex regex, string text, Func<string, string> normalize)
    {
        foreach (Match match in regex.Matches(text).Cast<Match>().Take(MaxValuesPerKind))
        {
            var value = normalize(match.Value);
            if (string.IsNullOrWhiteSpace(value)) continue;
            AddUnique(output, evidenceId, runId, kind, indicatorType, value, Context(text, match.Index, match.Length), match.Index);
        }
    }

    private static void AddUnique(AnalyzerOutput output, Guid evidenceId, Guid runId, ArtifactKind kind, IndicatorType indicatorType, string value, string context, long? offset = null)
    {
        if (output.Artifacts.Any(x => x.Kind == kind && x.Value.Equals(value, StringComparison.OrdinalIgnoreCase))) return;
        output.Artifacts.Add(new AnalysisArtifact { EvidenceId = evidenceId, AnalysisRunId = runId, Kind = kind, Name = kind.ToString(), Value = value, Context = context, Offset = offset, Confidence = ConfidenceLevel.Observed });
        if (kind is ArtifactKind.Url or ArtifactKind.Domain or ArtifactKind.IpAddress or ArtifactKind.Email or ArtifactKind.FileHash or ArtifactKind.NetworkEndpoint)
            output.Indicators.Add(new CaseIndicator { Type = indicatorType, Value = value, NormalizedValue = value.ToLowerInvariant(), Description = context, Confidence = ConfidenceLevel.Observed, EvidenceIds = [evidenceId] });
    }

    private static void AddScriptFunctions(AnalyzerOutput output, Guid evidenceId, Guid runId, string text)
    {
        foreach (Match match in FunctionRegex().Matches(text).Cast<Match>().Take(MaxValuesPerKind))
        {
            var name = match.Groups[1].Value;
            if (string.IsNullOrWhiteSpace(name) || output.Artifacts.Any(x => x.Kind == ArtifactKind.ScriptFunction && x.Value == name)) continue;
            output.Artifacts.Add(new AnalysisArtifact { EvidenceId = evidenceId, AnalysisRunId = runId, Kind = ArtifactKind.ScriptFunction, Name = "Función", Value = name, Context = Context(text, match.Index, match.Length), Offset = match.Index, Confidence = ConfidenceLevel.Observed });
        }
    }

    private static void AddCapabilities(AnalyzerOutput output, Guid evidenceId, Guid runId, string text)
    {
        var capabilities = new Dictionary<string, string[]>
        {
            ["Network request"] = ["fetch(", "XMLHttpRequest", "WebSocket("],
            ["Dynamic code execution"] = ["eval(", "new Function(", "createElement(\"script\")", "createElement('script')"],
            ["Browser storage"] = ["localStorage", "sessionStorage", "caches.open("],
            ["Compression"] = ["CompressionStream", "gzip"],
            ["Cryptography"] = ["crypto.subtle", "SHA-256", "RSA"],
            ["Process execution"] = ["Process.Start", "child_process", "exec(", "spawn("]
        };
        foreach (var capability in capabilities.Where(x => x.Value.Any(value => text.Contains(value, StringComparison.Ordinal))))
            output.Artifacts.Add(new AnalysisArtifact { EvidenceId = evidenceId, AnalysisRunId = runId, Kind = ArtifactKind.Capability, Name = "Capacidad", Value = capability.Key, Context = string.Join(", ", capability.Value.Where(value => text.Contains(value, StringComparison.Ordinal))), Confidence = ConfidenceLevel.Observed });
    }

    private static string NormalizeIp(string value) => IPAddress.TryParse(value, out var ip) ? ip.ToString() : string.Empty;
    private static bool IsScript(string name) => new[] { ".js", ".mjs", ".ts", ".php", ".ps1", ".cmd", ".bat", ".py", ".html", ".htm" }.Contains(Path.GetExtension(name).ToLowerInvariant());
    private static string Context(string text, int index, int length)
    {
        var start = Math.Max(0, index - 80);
        var end = Math.Min(text.Length, index + length + 80);
        return Regex.Replace(text[start..end], "\\s+", " ").Trim();
    }

    [GeneratedRegex(@"https?://[^\s<>""']+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)] private static partial Regex UrlRegex();
    [GeneratedRegex(@"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)] private static partial Regex EmailRegex();
    [GeneratedRegex(@"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])", RegexOptions.CultureInvariant)] private static partial Regex IpRegex();
    [GeneratedRegex(@"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b", RegexOptions.CultureInvariant)] private static partial Regex HashRegex();
    [GeneratedRegex(@"(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(", RegexOptions.CultureInvariant)] private static partial Regex FunctionRegex();
    [GeneratedRegex(@"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/=_-]{24,4096}(?![A-Za-z0-9+/=_-])", RegexOptions.CultureInvariant)] private static partial Regex EncodedTokenRegex();
}

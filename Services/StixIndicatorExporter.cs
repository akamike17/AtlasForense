using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization.Metadata;
using AtlasForense.Models;

namespace AtlasForense.Services;

public sealed class StixIndicatorExporter : IStixIndicatorExporter
{
    public StixExportResult Export(ForensicCase item)
    {
        var created = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
        var reportId = StixId("report", $"{item.Id:N}");
        var objects = new JsonArray();
        var indicators = 0;
        var skipped = 0;

        foreach (var indicator in item.Indicators.OrderBy(x => x.Type.ToString(), StringComparer.Ordinal).ThenBy(x => x.NormalizedValue, StringComparer.Ordinal))
        {
            var pattern = BuildPattern(indicator);
            if (pattern is null) { skipped++; continue; }
            indicators++;
            var id = StixId("indicator", $"{indicator.Type}|{indicator.NormalizedValue}");
            var node = new JsonObject
            {
                ["type"] = "indicator",
                ["spec_version"] = "2.1",
                ["id"] = id,
                ["created"] = created,
                ["modified"] = created,
                ["name"] = $"{indicator.Type}: {indicator.Value}",
                ["description"] = string.IsNullOrWhiteSpace(indicator.Description) ? "Indicador extraído por análisis estático de evidencia." : indicator.Description,
                ["indicator_types"] = new JsonArray("malicious-activity"),
                ["pattern"] = pattern,
                ["pattern_type"] = "stix",
                ["valid_from"] = created,
                ["confidence"] = ConfidenceScore(indicator.Confidence)
            };
            objects.Add(node);
        }

        var objectRefs = new JsonArray();
        foreach (var node in objects) objectRefs.Add(node!["id"]!.GetValue<string>());
        objects.Insert(0, new JsonObject
        {
            ["type"] = "report",
            ["spec_version"] = "2.1",
            ["id"] = reportId,
            ["created"] = created,
            ["modified"] = created,
            ["name"] = $"Informe forense {item.Folio}: {item.Title}",
            ["description"] = item.Report?.ExecutiveSummary is { Length: > 0 } summary ? summary : "Exportación machine-readable de indicadores del expediente.",
            ["report_types"] = new JsonArray("forensic"),
            ["published"] = created,
            ["object_refs"] = objectRefs
        });

        var bundle = new JsonObject
        {
            ["type"] = "bundle",
            ["id"] = StixId("bundle", $"{item.Id:N}|{item.Indicators.Count}"),
            ["objects"] = objects
        };

        var content = bundle.ToJsonString(new JsonSerializerOptions { WriteIndented = true, TypeInfoResolver = new DefaultJsonTypeInfoResolver(), Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(content))).ToLowerInvariant();
        return new StixExportResult(content, $"{item.Folio}-stix-2.1.json", hash, indicators, skipped);
    }

    private static string? BuildPattern(CaseIndicator indicator)
    {
        var value = indicator.Value.Replace("'", "\\'");
        return indicator.Type switch
        {
            IndicatorType.Url => $"[url:value = '{value}']",
            IndicatorType.Domain => $"[domain-name:value = '{value}']",
            IndicatorType.IpAddress => $"[ipv4-addr:value = '{value}']",
            IndicatorType.Email => $"[email-addr:value = '{value}']",
            IndicatorType.Hash => indicator.NormalizedValue.Length switch
            {
                32 => $"[file:hashes.MD5 = '{value}']",
                40 => $"[file:hashes.'SHA-1' = '{value}']",
                64 => $"[file:hashes.'SHA-256' = '{value}']",
                _ => null
            },
            IndicatorType.FileName => $"[file:name = '{value}']",
            IndicatorType.RegistryKey => $"[windows-registry-key:key = '{value}']",
            IndicatorType.Mutex => $"[mutex:name = '{value}']",
            _ => null
        };
    }

    private static int ConfidenceScore(ConfidenceLevel level) => level switch
    {
        ConfidenceLevel.Confirmed => 70,
        ConfidenceLevel.Corroborated => 85,
        ConfidenceLevel.Inferred => 40,
        _ => 30
    };

    private static string StixId(string type, string seed)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes($"{type}|{seed}"))[..16];
        bytes[7] = (byte)((bytes[7] & 0x0f) | 0x40);
        bytes[8] = (byte)((bytes[8] & 0x3f) | 0x80);
        return $"{type}--{new Guid(bytes):D}";
    }
}

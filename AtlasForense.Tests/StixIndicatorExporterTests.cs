using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using AtlasForense.Models;
using AtlasForense.Services;
using Xunit;

namespace AtlasForense.Tests;

public sealed class StixIndicatorExporterTests
{
    [Fact]
    public void Export_BuildsDeterministicBundleWithMappedPatterns()
    {
        var item = BuildCase();
        var exporter = new StixIndicatorExporter();

        var first = exporter.Export(item);
        var second = exporter.Export(item);

        Assert.Equal(9, first.Indicators);
        Assert.Equal(1, first.Skipped);
        Assert.EndsWith("-stix-2.1.json", first.FileName);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(first.Content))).ToLowerInvariant(), first.Sha256);

        var bundle = JsonNode.Parse(first.Content)!.AsObject();
        Assert.Equal("bundle", bundle["type"]!.GetValue<string>());
        Assert.StartsWith("bundle--", bundle["id"]!.GetValue<string>());
        var objects = bundle["objects"]!.AsArray();
        Assert.Equal(10, objects.Count);
        var report = objects[0]!.AsObject();
        var indicators = objects.Skip(1).ToList();
        Assert.Equal("report", report["type"]!.GetValue<string>());
        Assert.Equal(9, report["object_refs"]!.AsArray().Count);
        Assert.Contains(indicators, x => x!["pattern"]!.GetValue<string>() == "[url:value = 'http://malicious.example/gate']");
        Assert.Contains(indicators, x => x!["pattern"]!.GetValue<string>() == "[domain-name:value = 'malicious.example']");
        Assert.Contains(indicators, x => x!["pattern"]!.GetValue<string>() == "[ipv4-addr:value = '198.51.100.7']");
        Assert.Contains(indicators, x => x!["pattern"]!.GetValue<string>() == "[email-addr:value = 'cebo@malicious.example']");
        Assert.Contains(indicators, x => x!["pattern"]!.GetValue<string>().StartsWith("[file:hashes.'SHA-256' = '"));
        Assert.Contains(indicators, x => x!["pattern"]!.GetValue<string>().StartsWith("[file:hashes.MD5 = '"));
        Assert.Contains(indicators, x => x!["pattern"]!.GetValue<string>() == "[windows-registry-key:key = 'HKLM\\Software\\Persist']");
        Assert.Contains(indicators, x => x!["pattern"]!.GetValue<string>() == "[mutex:name = 'Global\\Lock']");
        Assert.All(indicators, x => Assert.Equal("indicator", x!["type"]!.GetValue<string>()));
        Assert.All(indicators, x => Assert.StartsWith("indicator--", x!["id"]!.GetValue<string>()));

        Assert.Equal(IdsOf(first.Content), IdsOf(second.Content));
    }

    [Fact]
    public void Export_EscapesQuotesInPatterns()
    {
        var item = BuildCase();
        item.Indicators.Add(new CaseIndicator { Type = IndicatorType.FileName, Value = "weird'name.exe", NormalizedValue = "weird'name.exe", Confidence = ConfidenceLevel.Observed, EvidenceIds = [item.Id] });

        var result = new StixIndicatorExporter().Export(item);

        var bundle = JsonNode.Parse(result.Content);
        Assert.Contains(bundle!["objects"]!.AsArray().Skip(1), x => x!["pattern"]!.GetValue<string>() == "[file:name = 'weird\\'name.exe']");
    }

    private static List<string> IdsOf(string content) => JsonNode.Parse(content)!["objects"]!.AsArray().Select(x => x!["id"]!.GetValue<string>()).ToList();

    private static ForensicCase BuildCase() => new()
    {
        Folio = "ATL-2026-001",
        Title = "Validación STIX",
        Indicators =
        [
            new() { Type = IndicatorType.Url, Value = "http://malicious.example/gate", NormalizedValue = "http://malicious.example/gate", Confidence = ConfidenceLevel.Observed },
            new() { Type = IndicatorType.Domain, Value = "malicious.example", NormalizedValue = "malicious.example", Confidence = ConfidenceLevel.Confirmed },
            new() { Type = IndicatorType.IpAddress, Value = "198.51.100.7", NormalizedValue = "198.51.100.7", Confidence = ConfidenceLevel.Corroborated },
            new() { Type = IndicatorType.Email, Value = "cebo@malicious.example", NormalizedValue = "cebo@malicious.example", Confidence = ConfidenceLevel.Inferred },
            new() { Type = IndicatorType.Hash, Value = new string('a', 64), NormalizedValue = new string('a', 64), Confidence = ConfidenceLevel.Observed },
            new() { Type = IndicatorType.Hash, Value = new string('b', 32), NormalizedValue = new string('b', 32), Confidence = ConfidenceLevel.Observed },
            new() { Type = IndicatorType.RegistryKey, Value = "HKLM\\Software\\Persist", NormalizedValue = "hklm\\software\\persist", Confidence = ConfidenceLevel.Observed },
            new() { Type = IndicatorType.Mutex, Value = "Global\\Lock", NormalizedValue = "global\\lock", Confidence = ConfidenceLevel.Observed },
            new() { Type = IndicatorType.Other, Value = "webshell-heuristics", NormalizedValue = "webshell-heuristics", Confidence = ConfidenceLevel.Inferred },
            new() { Type = IndicatorType.FileName, Value = "payload.exe", NormalizedValue = "payload.exe", Confidence = ConfidenceLevel.Observed }
        ]
    };
}

using System.IO.Compression;
using System.Security.Cryptography;
using AtlasForense.Forensics;
using AtlasForense.Models;
using AtlasForense.Services;
using Microsoft.Extensions.Options;
using Xunit;

namespace AtlasForense.Tests;

public sealed class ZipInventoryAnalyzerTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"atlas-zip-analysis-{Guid.NewGuid():N}");
    private readonly ZipInventoryAnalyzer _analyzer;

    public ZipInventoryAnalyzerTests()
    {
        Directory.CreateDirectory(_root);
        var inspector = new ArchiveSafetyInspector(Options.Create(new ForensicStorageOptions { MaxArchiveEntries = 20, MaxArchiveExpandedBytes = 8 * 1024 * 1024, MaxCompressionRatio = 100, MaxArchiveDepth = 4 }));
        _analyzer = new ZipInventoryAnalyzer(inspector);
    }

    [Fact]
    public async Task Analyzer_InventoriesHashesAndTimesEntriesWithoutExtracting()
    {
        var path = Path.Combine(_root, "evidence.zip");
        var timestamp = new DateTimeOffset(2025, 1, 2, 4, 6, 8, TimeSpan.Zero);
        using (var archive = ZipFile.Open(path, ZipArchiveMode.Create))
        {
            Write(archive, "folder/one.txt", "known evidence", timestamp);
            Write(archive, "folder/two.txt", "known evidence", timestamp);
        }
        var before = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(path)));
        var evidence = new EvidenceItem { Id = Guid.NewGuid(), Identifier = "EV-ZIP", OriginalFileName = "evidence.zip" };

        var output = await _analyzer.AnalyzeAsync(new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), evidence, path, default));

        Assert.Equal(before, Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(path))));
        Assert.Equal(2, output.Artifacts.Count(x => x.Name == "Entrada ZIP"));
        Assert.Equal(2, output.Artifacts.Count(x => x.Name == "SHA-256 de entrada"));
        Assert.Single(output.Indicators, x => x.Type == IndicatorType.Hash);
        Assert.Equal(2, output.Events.Count);
        Assert.All(output.Events, x => Assert.Equal(timestamp, x.OccurredAtUtc));
        Assert.DoesNotContain(Directory.EnumerateFiles(_root), x => !x.EndsWith("evidence.zip"));
    }

    [Fact]
    public async Task Analyzer_RefusesUnsafeArchiveEvenWhenExtensionMatches()
    {
        var path = Path.Combine(_root, "unsafe.zip");
        using (var archive = ZipFile.Open(path, ZipArchiveMode.Create)) Write(archive, "../escape.txt", "x", DateTimeOffset.UtcNow);
        var evidence = new EvidenceItem { OriginalFileName = "unsafe.zip" };

        var exception = await Assert.ThrowsAsync<InvalidDataException>(() => _analyzer.AnalyzeAsync(
            new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), evidence, path, default)));

        Assert.Contains("no superó", exception.Message);
    }

    private static void Write(ZipArchive archive, string name, string value, DateTimeOffset timestamp)
    {
        var entry = archive.CreateEntry(name, CompressionLevel.Optimal);
        entry.LastWriteTime = timestamp;
        using var writer = new StreamWriter(entry.Open());
        writer.Write(value);
    }

    public void Dispose() { if (Directory.Exists(_root)) Directory.Delete(_root, true); }
}

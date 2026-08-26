using System.IO.Compression;
using AtlasForense.Models;
using AtlasForense.Services;
using Microsoft.Extensions.Options;
using Xunit;

namespace AtlasForense.Tests;

public sealed class ArchiveSafetyTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"atlas-archive-{Guid.NewGuid():N}");
    private readonly ArchiveSafetyInspector _inspector;

    public ArchiveSafetyTests()
    {
        Directory.CreateDirectory(_root);
        _inspector = new ArchiveSafetyInspector(Options.Create(new ForensicStorageOptions { MaxArchiveEntries = 20, MaxArchiveExpandedBytes = 4 * 1024 * 1024, MaxCompressionRatio = 50, MaxArchiveDepth = 3 }));
    }

    [Fact]
    public async Task Inspector_AcceptsBoundedInventory()
    {
        var path = CreateZip(archive => WriteEntry(archive, "folder/evidence.txt", "known evidence"));
        var result = await _inspector.InspectZipAsync(path, default);
        Assert.True(result.Safe, result.Message); Assert.Equal(1, result.EntryCount);
    }

    [Theory]
    [InlineData("../escape.txt")]
    [InlineData("folder/../../escape.txt")]
    [InlineData("C:/absolute.txt")]
    public async Task Inspector_RejectsTraversalAndAbsolutePaths(string name)
    {
        var path = CreateZip(archive => WriteEntry(archive, name, "x"));
        Assert.False((await _inspector.InspectZipAsync(path, default)).Safe);
    }

    [Fact]
    public async Task Inspector_RejectsDuplicateNamesSymlinksBombsAndCorruption()
    {
        var duplicate = CreateZip(archive => { WriteEntry(archive, "same.txt", "a"); WriteEntry(archive, "same.txt", "b"); });
        var symlink = CreateZip(archive => { var entry = archive.CreateEntry("link"); entry.ExternalAttributes = 0xA000 << 16; });
        var bomb = CreateZip(archive => WriteEntry(archive, "bomb.txt", new string('A', 1024 * 1024)));
        var corrupt = Path.Combine(_root, "corrupt.zip"); await File.WriteAllBytesAsync(corrupt, "PK\x03\x04truncated"u8.ToArray());

        Assert.False((await _inspector.InspectZipAsync(duplicate, default)).Safe);
        Assert.False((await _inspector.InspectZipAsync(symlink, default)).Safe);
        Assert.False((await _inspector.InspectZipAsync(bomb, default)).Safe);
        Assert.False((await _inspector.InspectZipAsync(corrupt, default)).Safe);
    }

    private string CreateZip(Action<ZipArchive> content)
    {
        var path = Path.Combine(_root, $"{Guid.NewGuid():N}.zip");
        using var archive = ZipFile.Open(path, ZipArchiveMode.Create); content(archive); return path;
    }
    private static void WriteEntry(ZipArchive archive, string name, string content) { using var writer = new StreamWriter(archive.CreateEntry(name, CompressionLevel.Optimal).Open()); writer.Write(content); }
    public void Dispose() { if (Directory.Exists(_root)) Directory.Delete(_root, true); }
}

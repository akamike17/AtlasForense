using System.Buffers.Binary;
using System.Text;
using AtlasForense.Forensics;
using AtlasForense.Models;
using Xunit;

namespace AtlasForense.Tests;

public sealed class PrefetchAnalyzerTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"atlas-pf-{Guid.NewGuid():N}.pf");

    [Fact]
    public async Task Analyzer_ExtractsExecutableHashReferencesAndRunTimes()
    {
        await File.WriteAllBytesAsync(_path, BuildPrefetch(declaredMatches: true));
        var evidence = new EvidenceItem { Id = Guid.NewGuid(), Identifier = "EV-PF", OriginalFileName = "MALWARE.EXE-1234ABCD.pf" };

        var output = await new PrefetchAnalyzer().AnalyzeAsync(new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), evidence, _path, default));

        Assert.Contains(output.Artifacts, x => x.Name == "Ejecutable Prefetch" && x.Value == "MALWARE.EXE" && x.Context.Contains("0x1234ABCD"));
        Assert.Contains(output.Entities, x => x.Type == "File" && x.Value == "malware.exe");
        Assert.Equal(2, output.Artifacts.Count(x => x.Name == "Archivo referenciado"));
        Assert.Contains(output.Artifacts, x => x.Name == "Archivo referenciado" && x.Value.EndsWith("NTDLL.DLL"));
        Assert.Contains(output.Artifacts, x => x.Name == "Conteo de ejecuciones" && x.Value == "5");
        Assert.Equal(2, output.Artifacts.Count(x => x.Name == "Última ejecución declarada"));
        Assert.Equal(2, output.Events.Count);
        Assert.Contains(output.Events, x => x.OccurredAtUtc == new DateTimeOffset(2024, 4, 5, 8, 30, 0, TimeSpan.Zero));
        Assert.Contains(output.Events, x => x.OccurredAtUtc == new DateTimeOffset(2024, 4, 6, 9, 0, 0, TimeSpan.Zero));
        Assert.Contains("Prefetch v26", output.Summary);
    }

    [Fact]
    public async Task Analyzer_FlagsDeclaredSizeMismatch()
    {
        await File.WriteAllBytesAsync(_path, BuildPrefetch(declaredMatches: false));
        var evidence = new EvidenceItem { OriginalFileName = "MALWARE.EXE-1234ABCD.pf" };

        var output = await new PrefetchAnalyzer().AnalyzeAsync(new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), evidence, _path, default));

        Assert.Contains(output.Artifacts, x => x.Name == "Tamaño Prefetch inconsistente" && x.Confidence == ConfidenceLevel.Inferred);
    }

    [Theory]
    [InlineData(0x40)]
    [InlineData(0x7f)]
    public async Task Analyzer_RejectsTruncatedOrUnsupportedPrefetch(int variant)
    {
        byte[] data = variant == 0x40 ? new byte[0x40] : BuildPrefetch(declaredMatches: true);
        if (variant == 0x7f) BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0), 99);
        await File.WriteAllBytesAsync(_path, data);
        var evidence = new EvidenceItem { OriginalFileName = "sample.pf" };

        await Assert.ThrowsAsync<InvalidDataException>(() => new PrefetchAnalyzer().AnalyzeAsync(
            new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), evidence, _path, default)));
    }

    [Theory]
    [InlineData("CMD.EXE-087B4001.pf", "", true)]
    [InlineData("unknown", "PREFETCH", true)]
    [InlineData("unknown", "Unknown", false)]
    [InlineData("documento.pdf", "", false)]
    public void Compatibility_UsesExtensionOrDetectedType(string name, string detectedType, bool expected) =>
        Assert.Equal(expected, new PrefetchAnalyzer().CanAnalyze(new EvidenceItem { OriginalFileName = name, DetectedFileType = detectedType }));

    private static byte[] BuildPrefetch(bool declaredMatches)
    {
        var data = new byte[0x300];
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0), 26);
        "SCCA"u8.CopyTo(data.AsSpan(4));
        Encoding.Unicode.GetBytes("MALWARE.EXE").CopyTo(data.AsSpan(12));
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x48), 0x1234abcd);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x4c), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x64), 0x100);

        var strings = "\\DEVICE\\HARDDISKVOLUME2\\WINDOWS\\SYSTEM32\\NTDLL.DLL\0\\DEVICE\\HARDDISKVOLUME2\\WINDOWS\\SYSTEM32\\KERNEL32.DLL\0";
        var stringBytes = Encoding.Unicode.GetBytes(strings);
        stringBytes.CopyTo(data.AsSpan(0x100));
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x68), (uint)stringBytes.Length);

        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x7c), 5);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(0x80), (ulong)new DateTime(2024, 4, 5, 8, 30, 0, DateTimeKind.Utc).ToFileTimeUtc());
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(0x88), (ulong)new DateTime(2024, 4, 6, 9, 0, 0, DateTimeKind.Utc).ToFileTimeUtc());
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(8), declaredMatches ? (uint)data.Length : 0xdead);
        return data;
    }

    public void Dispose() { if (File.Exists(_path)) File.Delete(_path); }
}

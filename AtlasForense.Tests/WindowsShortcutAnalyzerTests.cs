using System.Buffers.Binary;
using System.Text;
using AtlasForense.Forensics;
using AtlasForense.Models;
using Xunit;

namespace AtlasForense.Tests;

public sealed class WindowsShortcutAnalyzerTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"atlas-link-{Guid.NewGuid():N}.lnk");

    [Fact]
    public async Task Analyzer_ExtractsTargetArgumentsPathsAndFileTimesWithoutResolution()
    {
        var expected = new DateTimeOffset(2025, 4, 5, 6, 7, 8, TimeSpan.Zero);
        await File.WriteAllBytesAsync(_path, BuildLink(expected));
        var evidence = new EvidenceItem { Id = Guid.NewGuid(), Identifier = "EV-LNK", OriginalFileName = "startup.lnk" };

        var output = await new WindowsShortcutAnalyzer().AnalyzeAsync(new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), evidence, _path, default));

        Assert.Contains(output.Artifacts, x => x.Name == "Ruta base local" && x.Value == @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe");
        Assert.Contains(output.Artifacts, x => x.Name == "Argumentos" && x.Value.Contains("-EncodedCommand"));
        Assert.Contains(output.Artifacts, x => x.Name == "Patrón de argumentos" && x.Value == "PowerShell con contenido codificado" && x.Confidence == ConfidenceLevel.Inferred);
        Assert.Contains(output.Entities, x => x.Type == "FilePath" && x.Value.EndsWith("powershell.exe"));
        Assert.Equal(3, output.Events.Count);
        Assert.All(output.Events, x => Assert.Equal(expected, x.OccurredAtUtc));
        Assert.Contains("no resuelto ni ejecutado", output.Summary);
    }

    [Fact]
    public async Task Analyzer_RejectsTruncatedStringData()
    {
        var data = BuildLink(DateTimeOffset.UtcNow);
        Array.Resize(ref data, data.Length - 4);
        await File.WriteAllBytesAsync(_path, data);
        var evidence = new EvidenceItem { OriginalFileName = "broken.lnk" };

        await Assert.ThrowsAsync<InvalidDataException>(() => new WindowsShortcutAnalyzer().AnalyzeAsync(
            new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), evidence, _path, default)));
    }

    private static byte[] BuildLink(DateTimeOffset time)
    {
        const uint flags = 0x2 | 0x4 | 0x8 | 0x10 | 0x20 | 0x80;
        var header = new byte[76];
        BinaryPrimitives.WriteUInt32LittleEndian(header, 0x4c);
        new byte[] { 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 }.CopyTo(header, 4);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(20), flags);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(24), 0x20);
        for (var offset = 28; offset <= 44; offset += 8) BinaryPrimitives.WriteInt64LittleEndian(header.AsSpan(offset), time.ToFileTime());
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(52), 12345);
        var local = Encoding.Unicode.GetBytes(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" + "\0");
        var suffix = Encoding.Unicode.GetBytes("powershell.exe\0");
        var linkInfo = new byte[36 + local.Length + suffix.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(linkInfo, (uint)linkInfo.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(linkInfo.AsSpan(4), 0x24);
        BinaryPrimitives.WriteUInt32LittleEndian(linkInfo.AsSpan(8), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(linkInfo.AsSpan(28), 36);
        BinaryPrimitives.WriteUInt32LittleEndian(linkInfo.AsSpan(32), (uint)(36 + local.Length));
        local.CopyTo(linkInfo, 36); suffix.CopyTo(linkInfo, 36 + local.Length);
        var result = new List<byte>(header);
        result.AddRange(linkInfo);
        AddUnicode(result, "Persistencia de laboratorio");
        AddUnicode(result, @"..\WindowsPowerShell\v1.0\powershell.exe");
        AddUnicode(result, @"C:\Windows\System32");
        AddUnicode(result, "-NoProfile -EncodedCommand SQBFAFgA");
        return result.ToArray();
    }

    private static void AddUnicode(List<byte> target, string value)
    {
        var prefix = new byte[2]; BinaryPrimitives.WriteUInt16LittleEndian(prefix, (ushort)value.Length); target.AddRange(prefix); target.AddRange(Encoding.Unicode.GetBytes(value));
    }

    public void Dispose() { if (File.Exists(_path)) File.Delete(_path); }
}

using System.Buffers.Binary;
using System.Text;
using AtlasForense.Forensics;
using AtlasForense.Models;
using Xunit;

namespace AtlasForense.Tests;

public sealed class EvtxStructureAnalyzerTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"atlas-evtx-{Guid.NewGuid():N}.evtx");

    [Fact]
    public async Task Analyzer_ParsesChunksRecordsTimestampsAndStrings()
    {
        await File.WriteAllBytesAsync(_path, BuildEvtx());
        var evidence = new EvidenceItem { Id = Guid.NewGuid(), Identifier = "EV-EVTX", OriginalFileName = "Security.evtx" };

        var output = await new EvtxStructureAnalyzer().AnalyzeAsync(new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), evidence, _path, default));

        Assert.Contains(output.Artifacts, x => x.Name == "Cabecera EVTX" && x.Value == "v3.1");
        Assert.Contains(output.Artifacts, x => x.Name == "Chunk EVTX" && x.Value == "chunk 0" && x.Context.Contains("registros=2"));
        Assert.Contains(output.Artifacts, x => x.Name == "Cadena UTF-16" && x.Value == "Microsoft-Windows-Security-Auditing");
        Assert.Equal(2, output.Events.Count);
        Assert.Contains(output.Events, x => x.OccurredAtUtc == new DateTimeOffset(2024, 3, 1, 10, 0, 0, TimeSpan.Zero));
        Assert.Contains(output.Events, x => x.OccurredAtUtc == new DateTimeOffset(2024, 3, 2, 11, 0, 0, TimeSpan.Zero));
        Assert.Contains("muestra no ejecutada", output.Summary);
    }

    [Fact]
    public async Task Analyzer_FlagsDamagedChunkInsteadOfAborting()
    {
        var data = BuildEvtx();
        data[4096] = (byte)'X';
        await File.WriteAllBytesAsync(_path, data);
        var evidence = new EvidenceItem { OriginalFileName = "Security.evtx" };

        var output = await new EvtxStructureAnalyzer().AnalyzeAsync(new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), evidence, _path, default));

        Assert.Contains(output.Artifacts, x => x.Name == "Chunk EVTX dañado o ausente" && x.Confidence == ConfidenceLevel.Inferred);
    }

    [Theory]
    [InlineData(64)]
    [InlineData(4096)]
    public async Task Analyzer_RejectsTruncatedEvtx(int size)
    {
        var data = new byte[size];
        "ElfFile\0"u8.CopyTo(data.AsSpan(0, Math.Min(8, size)));
        await File.WriteAllBytesAsync(_path, data);
        var evidence = new EvidenceItem { OriginalFileName = "truncated.evtx" };

        await Assert.ThrowsAsync<InvalidDataException>(() => new EvtxStructureAnalyzer().AnalyzeAsync(
            new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), evidence, _path, default)));
    }

    [Theory]
    [InlineData("Security.evtx", "", true)]
    [InlineData("backup.EVTX", "", true)]
    [InlineData("archive", "EVTX", true)]
    [InlineData("documento.pdf", "", false)]
    public void Compatibility_UsesExtensionOrDetectedType(string name, string detectedType, bool expected) =>
        Assert.Equal(expected, new EvtxStructureAnalyzer().CanAnalyze(new EvidenceItem { OriginalFileName = name, DetectedFileType = detectedType }));

    private static byte[] BuildEvtx()
    {
        var data = new byte[4096 + 65536];
        "ElfFile\0"u8.CopyTo(data.AsSpan(0));
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(24), 3);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(32), 128);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(36), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(38), 3);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(40), (uint)data.Length);

        var chunk = 4096;
        "ElfChnk\0"u8.CopyTo(data.AsSpan(chunk));
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(chunk + 8), 1);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(chunk + 16), 2);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(chunk + 24), 1);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(chunk + 32), 2);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(chunk + 44), 640);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(chunk + 48), 768);

        WriteRecord(data, chunk + 512, 1, DateTime(2024, 3, 1, 10, 0), "Microsoft-Windows-Security-Auditing");
        WriteRecord(data, chunk + 640, 2, DateTime(2024, 3, 2, 11, 0), "EventRecordPayload");
        return data;
    }

    private static void WriteRecord(byte[] data, int offset, ulong number, long fileTime, string payload)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(offset), 0x2a2a);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(offset + 4), 128);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(offset + 8), number);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(offset + 16), (ulong)fileTime);
        Encoding.Unicode.GetBytes(payload).CopyTo(data.AsSpan(offset + 24));
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(offset + 124), 128);
    }

    private static long DateTime(int year, int month, int day, int hour, int minute) =>
        new DateTime(year, month, day, hour, minute, 0, DateTimeKind.Utc).ToFileTimeUtc();

    public void Dispose() { if (File.Exists(_path)) File.Delete(_path); }
}

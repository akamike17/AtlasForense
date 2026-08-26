using System.Buffers.Binary;
using System.Text;
using AtlasForense.Forensics;
using AtlasForense.Models;
using Xunit;

namespace AtlasForense.Tests;

public sealed class ElfStructureAnalyzerTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"atlas-elf-{Guid.NewGuid():N}.elf");

    [Fact]
    public async Task Analyzer_ExtractsStructureSegmentsSectionsDynamicAndAnomalies()
    {
        await File.WriteAllBytesAsync(_path, BuildElf64());
        var evidence = new EvidenceItem { Id = Guid.NewGuid(), Identifier = "EV-ELF", OriginalFileName = "sample.elf" };

        var output = await new ElfStructureAnalyzer().AnalyzeAsync(new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), evidence, _path, default));

        Assert.Contains(output.Artifacts, x => x.Name == "Clase ELF" && x.Value == "ELF64");
        Assert.Contains(output.Artifacts, x => x.Name == "Tipo ELF" && x.Value.Contains("ET_DYN"));
        Assert.Contains(output.Artifacts, x => x.Name == "Arquitectura ELF" && x.Value == "x86-64");
        Assert.Contains(output.Artifacts, x => x.Name == "Segmento LOAD" && x.Context.Contains("permisos=RWX"));
        Assert.Contains(output.Artifacts, x => x.Name == "Segmento RWX" && x.Confidence == ConfidenceLevel.Inferred);
        Assert.Contains(output.Artifacts, x => x.Name == "Sección ELF" && x.Value == ".text");
        Assert.Contains(output.Artifacts, x => x.Name == "Sección ELF" && x.Value == ".dynamic");
        Assert.Contains(output.Artifacts, x => x.Name == "Alta entropía de sección" && x.Value == ".text");
        Assert.Contains(output.Artifacts, x => x.Name == "Nombre de sección inusual" && x.Value == ".packed" && x.Confidence == ConfidenceLevel.Inferred);
        Assert.Contains(output.Artifacts, x => x.Name == "Biblioteca dinámica" && x.Value == "libc.so.6");
        Assert.Contains(output.Artifacts, x => x.Name == "Biblioteca dinámica" && x.Value == "libm.so.6");
        Assert.Contains(output.Entities, x => x.Type == "Module" && x.Value == "libc.so.6");
        Assert.Contains("muestra no cargada ni ejecutada", output.Summary);
    }

    [Fact]
    public async Task Analyzer_ParsesMinimalBigEndianElf32()
    {
        var data = new byte[52];
        data[0] = 0x7f; data[1] = (byte)'E'; data[2] = (byte)'L'; data[3] = (byte)'F';
        data[4] = 1; data[5] = 2; data[6] = 1;
        BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(16), 2);
        BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(18), 8);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(20), 1);
        BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(40), 52);
        await File.WriteAllBytesAsync(_path, data);
        var evidence = new EvidenceItem { OriginalFileName = "firmware.bin", DetectedFileType = "ELF" };

        var output = await new ElfStructureAnalyzer().AnalyzeAsync(new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), evidence, _path, default));

        Assert.Contains(output.Artifacts, x => x.Name == "Clase ELF" && x.Value == "ELF32" && x.Context.Contains("big-endian"));
        Assert.Contains(output.Artifacts, x => x.Name == "Tipo ELF" && x.Value.Contains("ET_EXEC"));
        Assert.Contains(output.Artifacts, x => x.Name == "Arquitectura ELF" && x.Value == "MIPS");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(51)]
    public async Task Analyzer_RejectsTruncatedOrSpoofedElf(int size)
    {
        var data = size == 0 ? [(byte)0x7f, (byte)'E', (byte)'L', (byte)'F'] : new byte[size];
        if (size > 4) { data[0] = 0x7f; data[1] = (byte)'E'; data[2] = (byte)'L'; data[3] = (byte)'F'; data[4] = 2; data[5] = 1; }
        await File.WriteAllBytesAsync(_path, data);
        var evidence = new EvidenceItem { OriginalFileName = "spoofed.elf" };

        await Assert.ThrowsAsync<InvalidDataException>(() => new ElfStructureAnalyzer().AnalyzeAsync(
            new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), evidence, _path, default)));
    }

    [Theory]
    [InlineData("binary.elf", "", true)]
    [InlineData("library.so", "", true)]
    [InlineData("noextension", "ELF", true)]
    [InlineData("document.pdf", "", false)]
    [InlineData("noextension", "Unknown", false)]
    public void Compatibility_UsesExtensionOrDetectedType(string name, string detectedType, bool expected) =>
        Assert.Equal(expected, new ElfStructureAnalyzer().CanAnalyze(new EvidenceItem { OriginalFileName = name, DetectedFileType = detectedType }));

    private static byte[] BuildElf64()
    {
        var data = new byte[2_500];
        data[0] = 0x7f; data[1] = (byte)'E'; data[2] = (byte)'L'; data[3] = (byte)'F';
        data[4] = 2; data[5] = 1; data[6] = 1;
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(16), 3);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(18), 0x3e);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(20), 1);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(24), 0x1000);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(32), 64);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(40), 0x800);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(52), 64);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(54), 56);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(56), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(58), 64);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(60), 6);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(62), 5);

        var ph = 64;
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(ph), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(ph + 4), 7);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(ph + 8), 0x200);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(ph + 32), 512);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(ph + 40), 512);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(ph + 48), 0x1000);

        new Random(42).NextBytes(data.AsSpan(0x200, 512));
        new Random(43).NextBytes(data.AsSpan(0x400, 256));
        var dynstr = new List<byte> { 0 };
        dynstr.AddRange(Encoding.ASCII.GetBytes("libc.so.6")); dynstr.Add(0);
        dynstr.AddRange(Encoding.ASCII.GetBytes("libm.so.6")); dynstr.Add(0);
        dynstr.ToArray().CopyTo(data.AsSpan(0x500));

        var dynamic = 0x600;
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(dynamic), 1);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(dynamic + 8), 1);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(dynamic + 16), 1);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(dynamic + 24), 11);

        var shstrtab = new List<byte> { 0 };
        shstrtab.AddRange(Encoding.ASCII.GetBytes(".text\0.packed\0.dynstr\0.dynamic\0.shstrtab"));
        shstrtab.Add(0);
        shstrtab.ToArray().CopyTo(data.AsSpan(0x700));

        WriteSection(data, 0x800 + 64, 1, 1, 0x200, 512);
        WriteSection(data, 0x800 + 128, 7, 1, 0x400, 256);
        WriteSection(data, 0x800 + 192, 15, 3, 0x500, (ulong)dynstr.Count);
        WriteSection(data, 0x800 + 256, 23, 6, 0x600, 48);
        WriteSection(data, 0x800 + 320, 32, 3, 0x700, (ulong)shstrtab.Count);
        return data;
    }

    private static void WriteSection(byte[] data, int offset, uint name, uint type, ulong fileOffset, ulong size)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(offset), name);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(offset + 4), type);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(offset + 24), fileOffset);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(offset + 32), size);
    }

    public void Dispose() { if (File.Exists(_path)) File.Delete(_path); }
}

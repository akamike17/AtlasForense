using System.Buffers.Binary;
using AtlasForense.Forensics;
using AtlasForense.Models;
using Xunit;

namespace AtlasForense.Tests;

public sealed class PortableExecutableAnalyzerTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"atlas-pe-{Guid.NewGuid():N}.exe");

    [Fact]
    public async Task Analyzer_ExtractsHeadersSectionsAnomaliesTimestampAndOverlay()
    {
        var bytes = BuildPe();
        await File.WriteAllBytesAsync(_path, bytes);
        var evidence = new EvidenceItem { Id = Guid.NewGuid(), Identifier = "EV-PE", OriginalFileName = "sample.exe" };

        var output = await new PortableExecutableAnalyzer().AnalyzeAsync(new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), evidence, _path, default));

        Assert.Contains(output.Artifacts, x => x.Name == "Arquitectura PE" && x.Value == "x64");
        Assert.Contains(output.Artifacts, x => x.Name == "Sección PE" && x.Value == ".packed" && x.Context.Contains("RWX"));
        Assert.Contains(output.Artifacts, x => x.Name == "Sección escribible y ejecutable" && x.Confidence == ConfidenceLevel.Inferred);
        Assert.Contains(output.Artifacts, x => x.Name == "Alta entropía de sección");
        Assert.Contains(output.Artifacts, x => x.Name == "Overlay PE" && x.Value == "76");
        Assert.Contains(output.Artifacts, x => x.Name == "Módulo importado" && x.Value == "KERNEL32.dll");
        Assert.Contains(output.Artifacts, x => x.Name == "API importada" && x.Value == "KERNEL32.dll!CreateProcessW");
        Assert.Contains(output.Artifacts, x => x.Name == "Capacidad por imports" && x.Value == "Ejecución de procesos" && x.Confidence == ConfidenceLevel.Inferred);
        Assert.Contains(output.Entities, x => x.Type == "Module" && x.Value == "kernel32.dll");
        Assert.Single(output.Events);
        Assert.Contains("muestra no cargada ni ejecutada", output.Summary);
    }

    [Fact]
    public async Task Analyzer_RejectsTruncatedOrSpoofedPe()
    {
        await File.WriteAllBytesAsync(_path, [(byte)'M', (byte)'Z', 0, 0]);
        var evidence = new EvidenceItem { OriginalFileName = "spoofed.exe" };

        await Assert.ThrowsAsync<InvalidDataException>(() => new PortableExecutableAnalyzer().AnalyzeAsync(
            new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), evidence, _path, default)));
    }

    [Theory]
    [InlineData("sample.exe", true)]
    [InlineData("driver.SYS", true)]
    [InlineData("renamed.bin", false)]
    public void Compatibility_IsConservativeByExtension(string name, bool expected) =>
        Assert.Equal(expected, new PortableExecutableAnalyzer().CanAnalyze(new EvidenceItem { OriginalFileName = name }));

    private static byte[] BuildPe()
    {
        var data = new byte[1_100];
        data[0] = (byte)'M'; data[1] = (byte)'Z';
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(0x3c), 0x80);
        "PE\0\0"u8.CopyTo(data.AsSpan(0x80));
        var coff = 0x84;
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(coff), 0x8664);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(coff + 2), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(coff + 4), 1_700_000_000);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(coff + 16), 0xf0);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(coff + 18), 0x2022);
        var optional = coff + 20;
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(optional), 0x20b);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(optional + 16), 0x1000);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(optional + 24), 0x140000000);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(optional + 68), 3);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(optional + 120), 0x1100);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(optional + 124), 40);
        var section = optional + 0xf0;
        ".packed\0"u8.CopyTo(data.AsSpan(section, 8));
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(section + 8), 512);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(section + 12), 0x1000);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(section + 16), 512);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(section + 20), 0x200);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(section + 36), 0xe0000020);
        new Random(173).NextBytes(data.AsSpan(0x200, 512));
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x300), 0x11a0);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x30c), 0x1180);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x310), 0x11b0);
        "KERNEL32.dll\0"u8.CopyTo(data.AsSpan(0x380));
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(0x3a0), 0x11c0);
        data[0x3c0] = 0; data[0x3c1] = 0;
        "CreateProcessW\0"u8.CopyTo(data.AsSpan(0x3c2));
        return data;
    }

    public void Dispose() { if (File.Exists(_path)) File.Delete(_path); }
}

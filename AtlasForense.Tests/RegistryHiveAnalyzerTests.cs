using System.Buffers.Binary;
using System.Text;
using AtlasForense.Forensics;
using AtlasForense.Models;
using Xunit;

namespace AtlasForense.Tests;

public sealed class RegistryHiveAnalyzerTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"atlas-hive-{Guid.NewGuid():N}.dat");

    [Fact]
    public async Task Analyzer_TraversesKeysValuesAndTimestamps()
    {
        await File.WriteAllBytesAsync(_path, BuildHive(secondSequence: 7));
        var evidence = new EvidenceItem { Id = Guid.NewGuid(), Identifier = "EV-REG", OriginalFileName = "NTUSER.DAT" };

        var output = await new RegistryHiveAnalyzer().AnalyzeAsync(new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), evidence, _path, default));

        Assert.Contains(output.Artifacts, x => x.Name == "Colmena de registro" && x.Value == "TESTHIVE");
        Assert.Contains(output.Artifacts, x => x.Name == "Clave de registro" && x.Value == "ROOT");
        Assert.Contains(output.Artifacts, x => x.Name == "Clave de registro" && x.Value == "ROOT\\Software");
        Assert.Contains(output.Artifacts, x => x.Name == "Valor de registro" && x.Value == "ROOT\\TestValue" && x.Context.Contains("REG_DWORD") && x.Context.Contains("dato=42"));
        Assert.Equal(2, output.Events.Count);
        Assert.Contains(output.Events, x => x.Title.Contains("colmena"));
        Assert.Contains("muestra no ejecutada", output.Summary);
    }

    [Fact]
    public async Task Analyzer_FlagsDivergentTransactionSequences()
    {
        await File.WriteAllBytesAsync(_path, BuildHive(secondSequence: 8));
        var evidence = new EvidenceItem { OriginalFileName = "NTUSER.DAT" };

        var output = await new RegistryHiveAnalyzer().AnalyzeAsync(new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), evidence, _path, default));

        Assert.Contains(output.Artifacts, x => x.Name == "Secuencias de transacción divergentes" && x.Confidence == ConfidenceLevel.Inferred);
    }

    [Fact]
    public async Task Analyzer_RejectsNonHiveContent()
    {
        await File.WriteAllBytesAsync(_path, Encoding.UTF8.GetBytes("esto no es una colmena de registro"));
        var evidence = new EvidenceItem { OriginalFileName = "NTUSER.DAT" };

        await Assert.ThrowsAsync<InvalidDataException>(() => new RegistryHiveAnalyzer().AnalyzeAsync(
            new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), evidence, _path, default)));
    }

    [Theory]
    [InlineData("NTUSER.DAT", "", true)]
    [InlineData("C:\\Users\\x\\ntuser.dat", "", true)]
    [InlineData("SOFTWARE", "", true)]
    [InlineData("backup.hiv", "", true)]
    [InlineData("cualquier", "REGF", true)]
    [InlineData("datos.txt", "", false)]
    [InlineData("archivo.dat", "Unknown", false)]
    public void Compatibility_UsesKnownNamesOrDetectedType(string name, string detectedType, bool expected) =>
        Assert.Equal(expected, new RegistryHiveAnalyzer().CanAnalyze(new EvidenceItem { OriginalFileName = name, DetectedFileType = detectedType }));

    private static byte[] BuildHive(uint secondSequence)
    {
        var data = new byte[8192];
        "regf"u8.CopyTo(data.AsSpan(0));
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(4), 7);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(8), secondSequence);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(12), (ulong)new DateTime(2024, 1, 15, 12, 0, 0, DateTimeKind.Utc).ToFileTimeUtc());
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(20), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(24), 5);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(36), 0x20);
        Encoding.Unicode.GetBytes("TESTHIVE").CopyTo(data.AsSpan(48));

        "hbin"u8.CopyTo(data.AsSpan(4096));
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(4096 + 8), 4096);

        var root = 4096 + 0x20;
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(root), -0x60);
        "nk"u8.CopyTo(data.AsSpan(root + 4));
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(root + 6), 0x0004);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(root + 8), (ulong)new DateTime(2024, 1, 15, 12, 0, 0, DateTimeKind.Utc).ToFileTimeUtc());
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(root + 4 + 0x14), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(root + 4 + 0x1c), 0x100);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(root + 4 + 0x24), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(root + 4 + 0x28), 0x180);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(root + 4 + 0x48), 8);
        Encoding.Unicode.GetBytes("ROOT").CopyTo(data.AsSpan(root + 4 + 0x4c));

        var list = 4096 + 0x100;
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(list), -0x10);
        "lf"u8.CopyTo(data.AsSpan(list + 4));
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(list + 6), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(list + 8), 0x200);

        var subkey = 4096 + 0x200;
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(subkey), -0x60);
        "nk"u8.CopyTo(data.AsSpan(subkey + 4));
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(subkey + 6), 0x0028);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(subkey + 4 + 0x1c), 0xffffffff);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(subkey + 4 + 0x28), 0xffffffff);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(subkey + 4 + 0x48), 8);
        Encoding.ASCII.GetBytes("Software").CopyTo(data.AsSpan(subkey + 4 + 0x4c));

        var values = 4096 + 0x180;
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(values), -0x08);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(values + 4), 0x280);

        var value = 4096 + 0x280;
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(value), -0x20);
        "vk"u8.CopyTo(data.AsSpan(value + 4));
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(value + 6), 9);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(value + 8), 4);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(value + 12), 0x300);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(value + 16), 4);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(value + 20), 1);
        Encoding.ASCII.GetBytes("TestValue").CopyTo(data.AsSpan(value + 4 + 0x14));

        var payload = 4096 + 0x300;
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(payload), -0x08);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(payload + 4), 42);
        return data;
    }

    public void Dispose() { if (File.Exists(_path)) File.Delete(_path); }
}

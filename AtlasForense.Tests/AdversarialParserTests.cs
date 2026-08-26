using System.IO.Compression;
using System.Text;
using AtlasForense.Forensics;
using AtlasForense.Models;
using AtlasForense.Services;
using Microsoft.Extensions.Options;
using Xunit;

namespace AtlasForense.Tests;

// Pruebas adversarias: el pipeline de análisis solo admite IOException,
// UnauthorizedAccessException e InvalidDataException; cualquier otra excepción
// rompería la solicitud. Estas entradas no deben producir nada fuera de eso,
// ni bucles infinitos, ni lecturas fuera de rango.
public sealed class AdversarialParserTests
{
    private static readonly IArchiveSafetyInspector Inspector =
        new ArchiveSafetyInspector(Options.Create(new ForensicStorageOptions { MaxArchiveEntries = 50, MaxArchiveExpandedBytes = 8 * 1024 * 1024, MaxCompressionRatio = 100, MaxArchiveDepth = 4 }));

    private static async Task RunAsync(IForensicAnalyzer analyzer, byte[] data, string fileName, string detectedType = "")
    {
        var path = Path.Combine(Path.GetTempPath(), $"atlas-adv-{Guid.NewGuid():N}.bin");
        await File.WriteAllBytesAsync(path, data);
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            try
            {
                await analyzer.AnalyzeAsync(new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(),
                    new EvidenceItem { Id = Guid.NewGuid(), OriginalFileName = fileName, DetectedFileType = detectedType }, path, cts.Token));
            }
            catch (OperationCanceledException) { Assert.Fail($"{analyzer.Id} no terminó en 15 s con {data.Length} bytes."); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException) { }
            catch (Exception ex) { Assert.Fail($"{analyzer.Id} lanzó {ex.GetType().Name}: {ex.Message}"); }
        }
        finally { File.Delete(path); }
    }

    private static async Task TruncationSweepAsync(IForensicAnalyzer analyzer, byte[] full, string fileName, int step, string detectedType = "")
    {
        for (var length = 0; length <= full.Length; length += Math.Max(step, 1))
            await RunAsync(analyzer, full[..length], fileName, detectedType);
        await RunAsync(analyzer, full, fileName, detectedType);
    }

    [Fact]
    public async Task Evtx_TruncatedRealExport_NeverEscapesControlledExceptions() =>
        await TruncationSweepAsync(new EvtxStructureAnalyzer(),
            await File.ReadAllBytesAsync(Corpus("real-eventlog.evtx")), "t.evtx", 512);

    [Fact]
    public async Task Registry_TruncatedRealHive_NeverEscapesControlledExceptions() =>
        await TruncationSweepAsync(new RegistryHiveAnalyzer(),
            await File.ReadAllBytesAsync(Corpus("real-hardware.hive")), "NTUSER.DAT", 256, "REGF");

    [Fact]
    public async Task PortableExecutable_TruncatedRealManagedPe_NeverEscapesControlledExceptions() =>
        await TruncationSweepAsync(new PortableExecutableAnalyzer(),
            await File.ReadAllBytesAsync(Path.Combine(AppContext.BaseDirectory, "AtlasForense.Tests.dll")), "t.dll", 1024);

    [Fact]
    public async Task Pdf_TruncatedDocument_NeverEscapesControlledExceptions()
    {
        var pdf = Encoding.ASCII.GetBytes("%PDF-1.7\n1 0 obj << /Type /Catalog /OpenAction << /S /JavaScript >> >> endobj\n2 0 obj << /EmbeddedFile >> endobj\n%%EOF\n");
        await TruncationSweepAsync(new PdfStructureAnalyzer(), pdf, "t.pdf", 7);
    }

    [Fact]
    public async Task Office_TruncatedOoxml_NeverEscapesControlledExceptions()
    {
        await using var stream = new MemoryStream();
        using (var zip = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = zip.CreateEntry("[Content_Types].xml");
            using (var writer = new StreamWriter(entry.Open())) writer.Write("<Types><Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/></Types>");
            var doc = zip.CreateEntry("word/document.xml");
            using (var writer = new StreamWriter(doc.Open())) writer.Write("<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"/>");
        }
        await TruncationSweepAsync(new OfficeDocumentAnalyzer(Inspector), stream.ToArray(), "t.docx", 32);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(7)]
    [InlineData(1234)]
    public async Task AllParsers_MagicFollowedByRandomBytes_AreContained(int seed)
    {
        var random = new Random(seed);
        var sizes = new[] { 0, 1, 7, 8, 15, 16, 64, 512, 4096, 4097, 65536 + 1 };
        var magics = new (byte[] Magic, IForensicAnalyzer Analyzer, string Name, string Type)[]
        {
            (Encoding.ASCII.GetBytes("\x7fELF"), new ElfStructureAnalyzer(), "t.elf", "ELF"),
            ("ElfFile\0"u8.ToArray(), new EvtxStructureAnalyzer(), "t.evtx", "EVTX"),
            ("regf"u8.ToArray(), new RegistryHiveAnalyzer(), "NTUSER.DAT", "REGF"),
            (new byte[] { 0x4d, 0x5a }, new PortableExecutableAnalyzer(), "t.exe", ""),
            (Encoding.ASCII.GetBytes("%PDF-"), new PdfStructureAnalyzer(), "t.pdf", "PDF"),
            ("SQLite format 3\0"u8.ToArray(), new SqliteForensicAnalyzer(), "t.sqlite", "SQLite"),
            (new byte[] { 0x50, 0x4b, 0x03, 0x04 }, new OfficeDocumentAnalyzer(Inspector), "t.docx", ""),
            (new byte[] { 0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1 }, new OfficeDocumentAnalyzer(Inspector), "t.doc", ""),
            (new byte[] { 26, 0, 0, 0, (byte)'S', (byte)'C', (byte)'C', (byte)'A' }, new PrefetchAnalyzer(), "t.pf", "PREFETCH")
        };
        foreach (var size in sizes)
            foreach (var (magic, analyzer, name, type) in magics)
            {
                var data = new byte[magic.Length + size];
                magic.CopyTo(data, 0);
                random.NextBytes(data.AsSpan(magic.Length));
                await RunAsync(analyzer, data, name, type);
            }
    }

    [Fact]
    public async Task Registry_CyclicSubkeyList_TerminatesWithinNodeBudget()
    {
        var data = new byte[8192];
        "regf"u8.CopyTo(data.AsSpan(0));
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(4), 1);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(8), 1);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(36), 0x20);
        "hbin"u8.CopyTo(data.AsSpan(4096));

        var root = 4096 + 0x20;
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(root), -0x60);
        "nk"u8.CopyTo(data.AsSpan(root + 4));
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(root + 4 + 0x14), 1);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(root + 4 + 0x1c), 0x100);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(root + 4 + 0x28), 0xffffffff);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(root + 4 + 0x48), 8);
        Encoding.Unicode.GetBytes("LOOPROOT").CopyTo(data.AsSpan(root + 4 + 0x4c));

        var list = 4096 + 0x100;
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(list), -0x10);
        "lf"u8.CopyTo(data.AsSpan(list + 4));
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(list + 6), 1);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(list + 8), 0x20);

        await RunAsync(new RegistryHiveAnalyzer(), data, "NTUSER.DAT", "REGF");
    }

    [Fact]
    public async Task Prefetch_OverflowStringSection_IsContained()
    {
        var data = new byte[0x200];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0), 26);
        "SCCA"u8.CopyTo(data.AsSpan(4));
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(8), (uint)data.Length);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x64), 0xfffffff0);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x68), 0xfffffff0);
        await RunAsync(new PrefetchAnalyzer(), data, "t.pf");
    }

    [Fact]
    public async Task Evtx_BackwardRecordOffsets_AreFlaggedWithoutThrowing()
    {
        var data = new byte[4096 + 65536];
        "ElfFile\0"u8.CopyTo(data.AsSpan(0));
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(32), 128);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(36), 1);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(38), 3);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(40), (uint)data.Length);
        "ElfChnk\0"u8.CopyTo(data.AsSpan(4096));
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(4096 + 44), 12);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(4096 + 48), 8);
        var output = await AnalyzeCapturingAsync(new EvtxStructureAnalyzer(), data, "t.evtx");
        Assert.Contains(output!.Artifacts, x => x.Name == "Offsets de registros inconsistentes");
    }

    [Fact]
    public async Task Office_XxeAttemptInRelationships_IsNeutralized()
    {
        await using var stream = new MemoryStream();
        using (var zip = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            Write(zip, "[Content_Types].xml", "<Types><Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/></Types>");
            Write(zip, "word/document.xml", "<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"/>");
            Write(zip, "word/_rels/document.xml.rels", "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///C:/windows/win.ini\">]><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink\" Target=\"&xxe;\" TargetMode=\"External\"/></Relationships>");
        }
        var output = await AnalyzeCapturingAsync(new OfficeDocumentAnalyzer(Inspector), stream.ToArray(), "xxe.docx");
        Assert.DoesNotContain(output!.Artifacts, x => x.Name == "Relación externa");
        Assert.DoesNotContain(output.Indicators, x => x.Value.Contains("win.ini"));
    }

    private static void Write(ZipArchive archive, string name, string content)
    {
        var entry = archive.CreateEntry(name, CompressionLevel.Optimal);
        using var writer = new StreamWriter(entry.Open(), Encoding.UTF8);
        writer.Write(content);
    }

    private static async Task<AnalyzerOutput?> AnalyzeCapturingAsync(IForensicAnalyzer analyzer, byte[] data, string fileName)
    {
        var path = Path.Combine(Path.GetTempPath(), $"atlas-adv-{Guid.NewGuid():N}.bin");
        await File.WriteAllBytesAsync(path, data);
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            try
            {
                return await analyzer.AnalyzeAsync(new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(),
                    new EvidenceItem { Id = Guid.NewGuid(), OriginalFileName = fileName }, path, cts.Token));
            }
            catch (OperationCanceledException) { Assert.Fail($"{analyzer.Id} no terminó en 15 s."); return null; }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException) { return null; }
            catch (Exception ex) { Assert.Fail($"{analyzer.Id} lanzó {ex.GetType().Name}: {ex.Message}"); return null; }
        }
        finally { File.Delete(path); }
    }

    private static string Corpus(string name) => Path.Combine(AppContext.BaseDirectory, "Corpus", name);
}

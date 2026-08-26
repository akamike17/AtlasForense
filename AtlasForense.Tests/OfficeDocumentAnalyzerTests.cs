using System.IO.Compression;
using System.Text;
using AtlasForense.Forensics;
using AtlasForense.Models;
using AtlasForense.Services;
using Microsoft.Extensions.Options;
using Xunit;

namespace AtlasForense.Tests;

public sealed class OfficeDocumentAnalyzerTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"atlas-office-{Guid.NewGuid():N}");
    private readonly OfficeDocumentAnalyzer _analyzer;

    public OfficeDocumentAnalyzerTests()
    {
        Directory.CreateDirectory(_root);
        var inspector = new ArchiveSafetyInspector(Options.Create(new ForensicStorageOptions { MaxArchiveEntries = 50, MaxArchiveExpandedBytes = 8 * 1024 * 1024, MaxCompressionRatio = 100, MaxArchiveDepth = 4 }));
        _analyzer = new OfficeDocumentAnalyzer(inspector);
    }

    [Fact]
    public async Task Analyzer_ParsesOoxmlMetadataMacrosRelationshipsAndEmbeddedObjects()
    {
        var path = Path.Combine(_root, "informe.docm");
        using (var archive = ZipFile.Open(path, ZipArchiveMode.Create))
        {
            Add(archive, "[Content_Types].xml", "<?xml version=\"1.0\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.ms-word.document.macroEnabled.main+xml\"/></Types>");
            Add(archive, "docProps/core.xml", "<?xml version=\"1.0\"?><cp:coreProperties xmlns:cp=\"http://schemas.openxmlformats.org/package/2006/metadata/core-properties\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:dcterms=\"http://purl.org/dc/terms/\"><dc:creator>Perito Uno</dc:creator><cp:lastModifiedBy>Perito Dos</cp:lastModifiedBy><dcterms:created>2024-05-01T10:00:00Z</dcterms:created><dcterms:modified>2024-05-02T11:30:00Z</dcterms:modified></cp:coreProperties>");
            Add(archive, "docProps/app.xml", "<?xml version=\"1.0\"?><Properties xmlns=\"http://schemas.openxmlformats.org/officeDocument/2006/extended-properties\"><Application>Microsoft Office Word</Application><AppVersion>16.0300</AppVersion><Company>Laboratorio</Company></Properties>");
            Add(archive, "word/_rels/document.xml.rels", "<?xml version=\"1.0\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink\" Target=\"http://malicious.example/pago\" TargetMode=\"External\"/><Relationship Id=\"rId2\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/image\" Target=\"media/img1.png\"/></Relationships>");
            Add(archive, "word/document.xml", "<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"/>");
            Add(archive, "word/vbaProject.bin", "MACRODATA");
            Add(archive, "word/embeddings/oleObject1.bin", "OLEOBJECT");
        }
        var evidence = new EvidenceItem { Id = Guid.NewGuid(), Identifier = "EV-OOXML", OriginalFileName = "informe.docm" };

        var output = await _analyzer.AnalyzeAsync(new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), evidence, path, default));

        Assert.Contains(output.Artifacts, x => x.Name == "Tipo OOXML" && x.Value == "Word habilitado para macros (DOCM)");
        Assert.Contains(output.Artifacts, x => x.Name == "Formato habilitado para macros" && x.Confidence == ConfidenceLevel.Inferred);
        Assert.Contains(output.Artifacts, x => x.Name == "Proyecto VBA" && x.Value == "word/vbaProject.bin");
        Assert.Contains(output.Artifacts, x => x.Name == "Metadato Creador" && x.Value == "Perito Uno");
        Assert.Contains(output.Artifacts, x => x.Name == "Metadato Última modificación por" && x.Value == "Perito Dos");
        Assert.Contains(output.Artifacts, x => x.Name == "Metadato Aplicación" && x.Value == "Microsoft Office Word");
        Assert.Contains(output.Artifacts, x => x.Name == "Metadato Organización" && x.Value == "Laboratorio");
        Assert.Contains(output.Artifacts, x => x.Name == "Relación externa" && x.Value == "http://malicious.example/pago");
        Assert.Contains(output.Artifacts, x => x.Name == "Objeto embebido" && x.Value == "word/embeddings/oleObject1.bin");
        Assert.Contains(output.Indicators, x => x.Type == IndicatorType.Url && x.Value == "http://malicious.example/pago");
        Assert.Contains(output.Entities, x => x.Type == "Person" && x.Value == "perito uno");
        Assert.Equal(2, output.Events.Count);
        Assert.Contains(output.Events, x => x.OccurredAtUtc == new DateTimeOffset(2024, 5, 1, 10, 0, 0, TimeSpan.Zero));
        Assert.Contains(output.Events, x => x.OccurredAtUtc == new DateTimeOffset(2024, 5, 2, 11, 30, 0, TimeSpan.Zero));
        Assert.Contains("contenido no ejecutado", output.Summary);
    }

    [Fact]
    public async Task Analyzer_ParsesOleCompoundFileDirectoryAndMacroSignals()
    {
        var path = Path.Combine(_root, "legado.doc");
        await File.WriteAllBytesAsync(path, BuildOle());
        var evidence = new EvidenceItem { Id = Guid.NewGuid(), Identifier = "EV-OLE", OriginalFileName = "legado.doc" };

        var output = await _analyzer.AnalyzeAsync(new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), evidence, path, default));

        Assert.Contains(output.Artifacts, x => x.Name == "CLSID raíz" && x.Context == "Word Document (Word 97-2003)");
        Assert.Contains(output.Artifacts, x => x.Name == "Stream" && x.Value == "WordDocument");
        Assert.Contains(output.Artifacts, x => x.Name == "Storage" && x.Value == "Macros");
        Assert.Contains(output.Artifacts, x => x.Name == "Stream" && x.Value == "_VBA_PROJECT");
        Assert.Contains(output.Artifacts, x => x.Name == "Formato binario Office" && x.Value == "WordDocument");
        Assert.Equal(2, output.Artifacts.Count(x => x.Name == "Posibles macros VBA" && x.Confidence == ConfidenceLevel.Inferred));
        Assert.Contains(output.Indicators, x => x.Value == "macro-vba-ole" && x.Confidence == ConfidenceLevel.Inferred);
        Assert.Contains("contenido no ejecutado", output.Summary);
    }

    [Theory]
    [InlineData("ilegible.doc")]
    [InlineData("falso.docx")]
    public async Task Analyzer_RejectsContentThatMatchesNeitherContainer(string name)
    {
        var path = Path.Combine(_root, name);
        var data = new byte[600];
        new Random(7).NextBytes(data);
        data[0] = 0x21;
        if (name.EndsWith(".doc"))
        {
            Array.Copy(new byte[] { 0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1 }, data, 8);
            data[28] = 0; data[29] = 0;
        }
        await File.WriteAllBytesAsync(path, data);
        var evidence = new EvidenceItem { OriginalFileName = name };

        await Assert.ThrowsAsync<InvalidDataException>(() => _analyzer.AnalyzeAsync(
            new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), evidence, path, default)));
    }

    [Theory]
    [InlineData("informe.docx", true)]
    [InlineData("plantilla.dotm", true)]
    [InlineData("libro.xlsm", true)]
    [InlineData("legado.doc", true)]
    [InlineData("antiguo.ppt", true)]
    [InlineData("documento.pdf", false)]
    public void Compatibility_CoversModernAndLegacyOfficeExtensions(string name, bool expected) =>
        Assert.Equal(expected, _analyzer.CanAnalyze(new EvidenceItem { OriginalFileName = name }));

    private static void Add(ZipArchive archive, string name, string content)
    {
        var entry = archive.CreateEntry(name, CompressionLevel.Optimal);
        using var writer = new StreamWriter(entry.Open(), Encoding.UTF8);
        writer.Write(content);
    }

    private static byte[] BuildOle()
    {
        var data = new byte[1_536];
        new byte[] { 0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1 }.CopyTo(data, 0);
        WriteUInt16(data, 24, 0x003e);
        WriteUInt16(data, 26, 3);
        WriteUInt16(data, 28, 0xfffe);
        WriteUInt16(data, 30, 9);
        WriteUInt16(data, 32, 6);
        WriteUInt32(data, 44, 1);
        WriteUInt32(data, 48, 1);
        WriteUInt32(data, 56, 4096);
        WriteUInt32(data, 60, 0xfffffffe);
        WriteUInt32(data, 68, 0xfffffffe);
        WriteUInt32(data, 76, 0);
        for (var index = 1; index < 109; index++) WriteUInt32(data, 76 + index * 4, 0xffffffff);

        WriteUInt32(data, 512, 0xfffffffd);
        WriteUInt32(data, 516, 0xfffffffe);
        for (var index = 2; index < 128; index++) WriteUInt32(data, 512 + index * 4, 0xffffffff);

        WriteDirectoryEntry(data, 1024, "Root Entry", 5, child: 1, clsid: new Guid("00020906-0000-0000-C000-000000000046"));
        WriteDirectoryEntry(data, 1152, "WordDocument", 2);
        WriteDirectoryEntry(data, 1280, "Macros", 1);
        WriteDirectoryEntry(data, 1408, "_VBA_PROJECT", 2);
        return data;
    }

    private static void WriteDirectoryEntry(byte[] data, int offset, string name, byte type, int child = -1, Guid? clsid = null)
    {
        var nameBytes = Encoding.Unicode.GetBytes(name);
        nameBytes.CopyTo(data, offset);
        WriteUInt16(data, offset + 64, (ushort)(nameBytes.Length + 2));
        data[offset + 66] = type;
        data[offset + 67] = 1;
        WriteUInt32(data, offset + 68, 0xffffffff);
        WriteUInt32(data, offset + 72, 0xffffffff);
        WriteUInt32(data, offset + 76, unchecked((uint)child));
        if (clsid.HasValue) clsid.Value.ToByteArray().CopyTo(data, offset + 80);
        WriteUInt32(data, offset + 116, 0xfffffffe);
    }

    private static void WriteUInt16(byte[] data, int offset, ushort value) => System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(offset), value);
    private static void WriteUInt32(byte[] data, int offset, uint value) => System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(offset), value);

    public void Dispose() { if (Directory.Exists(_root)) Directory.Delete(_root, true); }
}

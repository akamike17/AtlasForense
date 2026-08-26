using AtlasForense.Forensics;
using AtlasForense.Models;
using Xunit;

namespace AtlasForense.Tests;

public sealed class PdfStructureAnalyzerTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"atlas-pdf-{Guid.NewGuid():N}.pdf");

    [Fact]
    public async Task Analyzer_ExtractsVersionIncrementalUpdatesRisksAndUrls()
    {
        const string pdf = """
            %PDF-1.7
            1 0 obj
            << /Type /Catalog /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>
            endobj
            2 0 obj
            << /Names << /EmbeddedFiles << /Names [(f) << /EF << /F 3 0 R >> >>] >> >> >>
            endobj
            3 0 obj
            << /Type /EmbeddedFile >>
            stream
            endstream
            endobj
            4 0 obj
            << /URI (http://malicious.example/doc) >>
            endobj
            xref
            0 5
            trailer
            << /Root 1 0 R >>
            startxref
            123
            %%EOF
            5 0 obj
            << /Launch >>
            endobj
            %%EOF
            """;
        await File.WriteAllTextAsync(_path, pdf);
        var evidence = new EvidenceItem { Id = Guid.NewGuid(), Identifier = "EV-PDF", OriginalFileName = "informe.pdf" };

        var output = await new PdfStructureAnalyzer().AnalyzeAsync(new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), evidence, _path, default));

        Assert.Contains(output.Artifacts, x => x.Name == "Versión PDF" && x.Value == "1.7");
        Assert.Contains(output.Artifacts, x => x.Name == "Objetos indirectos" && x.Value == "5");
        Assert.Contains(output.Artifacts, x => x.Name == "Actualizaciones incrementales" && x.Value == "1" && x.Confidence == ConfidenceLevel.Inferred);
        Assert.Contains(output.Artifacts, x => x.Name == "JavaScript en PDF" && x.Confidence == ConfidenceLevel.Inferred);
        Assert.Contains(output.Artifacts, x => x.Name == "Acción automática de apertura");
        Assert.Contains(output.Artifacts, x => x.Name == "Archivo embebido");
        Assert.Contains(output.Artifacts, x => x.Name == "Lanzador externo");
        Assert.Contains(output.Artifacts, x => x.Name == "URL en PDF" && x.Value == "http://malicious.example/doc");
        Assert.Contains(output.Indicators, x => x.Type == IndicatorType.Url && x.Value == "http://malicious.example/doc");
        Assert.Contains(output.Indicators, x => x.Value == "/Launch" && x.Confidence == ConfidenceLevel.Observed);
        Assert.Contains("muestra no ejecutada", output.Summary);
    }

    [Theory]
    [InlineData("")]
    [InlineData("%PDF")]
    [InlineData("GIF89a not really a pdf file")]
    public async Task Analyzer_RejectsNonPdfContent(string content)
    {
        await File.WriteAllTextAsync(_path, content);
        var evidence = new EvidenceItem { OriginalFileName = "spoofed.pdf" };

        await Assert.ThrowsAsync<InvalidDataException>(() => new PdfStructureAnalyzer().AnalyzeAsync(
            new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), evidence, _path, default)));
    }

    [Theory]
    [InlineData("informe.pdf", "", true)]
    [InlineData("INFORME.PDF", "", true)]
    [InlineData("sinextension", "PDF", true)]
    [InlineData("sinextension", "Unknown", false)]
    [InlineData("documento.docx", "", false)]
    public void Compatibility_UsesExtensionOrDetectedType(string name, string detectedType, bool expected) =>
        Assert.Equal(expected, new PdfStructureAnalyzer().CanAnalyze(new EvidenceItem { OriginalFileName = name, DetectedFileType = detectedType }));

    public void Dispose() { if (File.Exists(_path)) File.Delete(_path); }
}

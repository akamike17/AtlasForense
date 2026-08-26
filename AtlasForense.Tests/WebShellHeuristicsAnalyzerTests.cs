using AtlasForense.Forensics;
using AtlasForense.Models;
using Xunit;

namespace AtlasForense.Tests;

public sealed class WebShellHeuristicsAnalyzerTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"atlas-ws-{Guid.NewGuid():N}.php");

    [Fact]
    public async Task Analyzer_FlagsClassicPhpWebShellPatterns()
    {
        await File.WriteAllTextAsync(_path, "<?php @eval($_POST['c']); $d = base64_decode($_GET['d']); system('whoami'); ?>");
        var evidence = new EvidenceItem { Id = Guid.NewGuid(), Identifier = "EV-WS", OriginalFileName = "cache.php" };

        var output = await new WebShellHeuristicsAnalyzer().AnalyzeAsync(new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), evidence, _path, default));

        Assert.Contains(output.Artifacts, x => x.Name == "Shell PHP por petición" && x.Value == "eval($_POST" && x.Confidence == ConfidenceLevel.Inferred);
        Assert.Contains(output.Artifacts, x => x.Name == "Ofuscación PHP" && x.Value == "base64_decode(");
        Assert.Contains(output.Artifacts, x => x.Name == "Ejecución de comandos" && x.Value == "system(");
        Assert.Contains(output.Artifacts, x => x.Name == "Entropía del guion");
        Assert.Contains(output.Indicators, x => x.Value == "webshell-heuristics" && x.Confidence == ConfidenceLevel.Inferred);
        Assert.Contains("confirmación manual requerida", output.Summary);
    }

    [Fact]
    public async Task Analyzer_ReportsCleanScriptWithoutFindings()
    {
        await File.WriteAllTextAsync(_path, "<?php echo htmlspecialchars('hola mundo'); ?>");
        var evidence = new EvidenceItem { OriginalFileName = "saludo.php" };

        var output = await new WebShellHeuristicsAnalyzer().AnalyzeAsync(new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), evidence, _path, default));

        Assert.Empty(output.Artifacts);
        Assert.Empty(output.Indicators);
        Assert.Contains("sin coincidencias", output.Summary);
    }

    [Fact]
    public async Task Analyzer_DetectsAspAndJspVariants()
    {
        var analyzer = new WebShellHeuristicsAnalyzer();
        var asp = Path.ChangeExtension(_path, ".asp");
        await File.WriteAllTextAsync(asp, "<% Execute(Request(\"cmd\")) %>");
        var jsp = Path.ChangeExtension(_path, ".jsp");
        await File.WriteAllTextAsync(jsp, "<% Runtime.getRuntime().exec(request.getParameter(\"c\")); %>");

        var aspOutput = await analyzer.AnalyzeAsync(new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), new EvidenceItem { OriginalFileName = "x.asp" }, asp, default));
        var jspOutput = await analyzer.AnalyzeAsync(new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), new EvidenceItem { OriginalFileName = "x.jsp" }, jsp, default));

        Assert.Contains(aspOutput.Artifacts, x => x.Name == "Shell ASP/ASP.NET");
        Assert.Contains(jspOutput.Artifacts, x => x.Name == "Shell JSP");
        File.Delete(asp); File.Delete(jsp);
    }

    [Theory]
    [InlineData("upload.php", true)]
    [InlineData("shell.ASPX", true)]
    [InlineData("cmd.jsp", true)]
    [InlineData("notas.txt", false)]
    [InlineData("documento.pdf", false)]
    public void Compatibility_CoversServerSideScriptExtensions(string name, bool expected) =>
        Assert.Equal(expected, new WebShellHeuristicsAnalyzer().CanAnalyze(new EvidenceItem { OriginalFileName = name }));

    public void Dispose() { if (File.Exists(_path)) File.Delete(_path); }
}

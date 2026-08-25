using System.Text;
using AtlasForense.Forensics;
using AtlasForense.Models;
using Xunit;

namespace AtlasForense.Tests;

public sealed class BinaryMetadataAnalyzerTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"atlas-binary-{Guid.NewGuid():N}.bin");

    [Fact]
    public async Task Analyzer_DetectsPeSignatureEntropyStringsAndIocsWithoutExecution()
    {
        var bytes = new byte[4096]; new Random(12345).NextBytes(bytes); bytes[0] = 0x4d; bytes[1] = 0x5a;
        Encoding.ASCII.GetBytes("https://binary.example.test/gate 203.0.113.42").CopyTo(bytes, 128);
        await File.WriteAllBytesAsync(_path, bytes);
        var evidence = new EvidenceItem { OriginalFileName = "sample.exe" };
        var runId = Guid.NewGuid();

        var output = await new BinaryMetadataAnalyzer().AnalyzeAsync(new AnalyzerContext(Guid.NewGuid(), runId, evidence, _path, default));

        Assert.Contains(output.Artifacts, x => x.Kind == ArtifactKind.FileType && x.Value.Contains("PE"));
        Assert.Contains(output.Artifacts, x => x.Kind == ArtifactKind.Entropy);
        Assert.Contains(output.Artifacts, x => x.Kind == ArtifactKind.Capability && x.Confidence == ConfidenceLevel.Inferred);
        Assert.Contains(output.Indicators, x => x.Type == IndicatorType.Url && x.Value.Contains("binary.example.test"));
        Assert.Contains(output.Indicators, x => x.Type == IndicatorType.IpAddress && x.Value == "203.0.113.42");
        Assert.Contains("muestra no ejecutada", output.Summary);
    }

    [Theory]
    [InlineData("255044462d", "PDF")]
    [InlineData("504b0304", "ZIP")]
    [InlineData("1f8b0800", "GZIP")]
    public async Task Analyzer_UsesMagicBytesInsteadOfExtension(string hex, string expected)
    {
        await File.WriteAllBytesAsync(_path, Convert.FromHexString(hex));
        var evidence = new EvidenceItem { OriginalFileName = "misleading.txt" };
        var output = await new BinaryMetadataAnalyzer().AnalyzeAsync(new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), evidence, _path, default));
        Assert.Contains(output.Artifacts, x => x.Kind == ArtifactKind.FileType && x.Value.Contains(expected));
    }

    public void Dispose() { if (File.Exists(_path)) File.Delete(_path); }
}

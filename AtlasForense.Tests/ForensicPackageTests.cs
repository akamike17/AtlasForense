using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using AtlasForense.Forensics;
using AtlasForense.Models;
using AtlasForense.Services;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.FileProviders;
using Xunit;

namespace AtlasForense.Tests;

public sealed class ForensicPackageTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"atlas-package-{Guid.NewGuid():N}");
    private readonly JsonForensicCaseService _cases;
    private readonly TestSigner _signer = new();

    public ForensicPackageTests()
    {
        Directory.CreateDirectory(_root);
        _cases = new JsonForensicCaseService(new TestEnvironment(_root), [new StaticTextAnalyzer()]);
    }

    [Fact]
    public async Task SignedPackage_IsIndependentlyVerifiedAndTamperingIsRejected()
    {
        var item = await CreateApprovedCase();
        var builder = new SignedForensicPackageBuilder(new TestEnvironment(_root), new MarkdownForensicReportBuilder(), _signer);

        var package = await builder.BuildAsync(item, default);

        Assert.True(package.Success, package.Message);
        Assert.Equal(64, package.Sha256.Length);
        var certificatePath = Path.Combine(_root, "trusted.cer");
        await File.WriteAllBytesAsync(certificatePath, _signer.PublicCertificate);
        var valid = await RunVerifier(package.Path, certificatePath);
        Assert.Equal(0, valid.ExitCode);
        Assert.Contains("PAQUETE VÁLIDO", valid.Output);

        using (var archive = ZipFile.Open(package.Path, ZipArchiveMode.Update))
        {
            var report = archive.GetEntry("report/report.md")!;
            report.Delete();
            await using var stream = archive.CreateEntry("report/report.md").Open();
            await stream.WriteAsync(Encoding.UTF8.GetBytes("modified report"));
        }
        var tampered = await RunVerifier(package.Path, certificatePath);
        Assert.NotEqual(0, tampered.ExitCode);
        Assert.Contains("NO VÁLIDO", tampered.Output);
    }

    [Fact]
    public async Task Package_BlocksChangedEvidenceBeforeSigning()
    {
        var item = await CreateApprovedCase();
        var evidence = item.Evidence.Single();
        await File.AppendAllTextAsync(Path.Combine(_root, "App_Data", "Evidence", item.Id.ToString("N"), evidence.StoredFileName), "tamper");
        var builder = new SignedForensicPackageBuilder(new TestEnvironment(_root), new MarkdownForensicReportBuilder(), _signer);

        var result = await builder.BuildAsync(item, default);

        Assert.False(result.Success);
        Assert.Contains("SHA-256", result.Message);
    }

    private async Task<ForensicCase> CreateApprovedCase()
    {
        var item = await _cases.CreateAsync(new CreateCaseInput { Title = "Package", RequestingOrganization = "Lab", LeadExaminer = "Examiner", Scope = "Known evidence" }, default);
        await _cases.AuthorizeAsync(new AuthorizeCaseInput { CaseId = item.Id, Authority = "Authority", Reference = "AUTH", ApprovedBy = "Supervisor" }, default);
        var bytes = Encoding.UTF8.GetBytes("forensic package evidence https://example.test");
        await _cases.AcquireAsync(new AcquireEvidenceInput { CaseId = item.Id, Description = "Evidence", SourceType = "File", SourceLocation = "Lab", AcquiredBy = "Examiner", AcquisitionMethod = "Verified copy", File = new FormFile(new MemoryStream(bytes), 0, bytes.Length, "File", "evidence.txt") }, default);
        await _cases.StartAnalysisAsync(item.Id, "Examiner", default);
        await _cases.AddFindingAsync(new FindingInput { CaseId = item.Id, Title = "Finding", Description = "Observed", TechnicalDetails = "Known", EvidenceReferences = item.Evidence.Single().Identifier, Analyst = "Examiner" }, default);
        await _cases.PrepareReportAsync(new ReportInput { CaseId = item.Id, ExecutiveSummary = "Summary", Methodology = "Static", Conclusions = "Conclusion", Recommendations = "Retain", PreparedBy = "Examiner" }, default);
        await _cases.ReviewReportAsync(item.Id, "Reviewer", true, "Approved", default);
        return item;
    }

    private static async Task<(int ExitCode, string Output)> RunVerifier(string package, string certificate)
    {
        var repository = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", ".."));
        var verifier = Path.Combine(repository, "AtlasForense.Verifier", "bin", "Release", "net8.0", "AtlasForense.Verifier.dll");
        var start = new ProcessStartInfo("dotnet") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        start.ArgumentList.Add(verifier); start.ArgumentList.Add(package); start.ArgumentList.Add(certificate);
        using var process = Process.Start(start)!;
        var output = await process.StandardOutput.ReadToEndAsync() + await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        return (process.ExitCode, output);
    }

    public void Dispose() { _signer.Dispose(); if (Directory.Exists(_root)) Directory.Delete(_root, true); }

    private sealed class TestSigner : IForensicPackageSigner, IDisposable
    {
        private readonly X509Certificate2 _certificate;
        public TestSigner() { using var rsa = RSA.Create(2048); var request = new CertificateRequest("CN=AtlasForense Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1); _certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1)); }
        public bool IsAvailable => true;
        public byte[] PublicCertificate => _certificate.Export(X509ContentType.Cert);
        public PackageSignature Sign(ReadOnlySpan<byte> manifest) { using var rsa = _certificate.GetRSAPrivateKey()!; var certificate = PublicCertificate; return new(rsa.SignData(manifest, HashAlgorithmName.SHA256, RSASignaturePadding.Pss), certificate, "RSA-PSS-SHA256", Convert.ToHexString(SHA256.HashData(certificate)).ToLowerInvariant()); }
        public void Dispose() => _certificate.Dispose();
    }

    private sealed class TestEnvironment : IWebHostEnvironment
    {
        public TestEnvironment(string root) { ContentRootPath = root; WebRootPath = Path.Combine(root, "wwwroot"); Directory.CreateDirectory(WebRootPath); ContentRootFileProvider = new PhysicalFileProvider(root); WebRootFileProvider = new PhysicalFileProvider(WebRootPath); }
        public string ApplicationName { get; set; } = "AtlasForense.Tests"; public IFileProvider WebRootFileProvider { get; set; } public string WebRootPath { get; set; }
        public string EnvironmentName { get; set; } = "Testing"; public string ContentRootPath { get; set; } public IFileProvider ContentRootFileProvider { get; set; }
    }
}

using System.Text;
using AtlasForense.Models;
using AtlasForense.Services;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Options;
using Xunit;

namespace AtlasForense.Tests;

public sealed class ForensicRetentionTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"atlas-retention-{Guid.NewGuid():N}");

    public ForensicRetentionTests() => Directory.CreateDirectory(_root);

    private JsonForensicCaseService CreateService(int retentionDays) =>
        new(new RetentionEnvironment(_root), storageOptions: Options.Create(new ForensicStorageOptions { RetentionDays = retentionDays }));

    private static async Task<Guid> CloseCaseAsync(JsonForensicCaseService service)
    {
        var item = await service.CreateAsync(new CreateCaseInput { Title = "Retention", RequestingOrganization = "Lab", LeadExaminer = "Examiner", Scope = "Retention" }, default);
        await service.AuthorizeAsync(new AuthorizeCaseInput { CaseId = item.Id, Authority = "Auth", Reference = "R1", ApprovedBy = "Supervisor" }, default);
        var bytes = Encoding.UTF8.GetBytes("retention evidence");
        await service.AcquireAsync(new AcquireEvidenceInput { CaseId = item.Id, Description = "Ev", SourceType = "Test", SourceLocation = "Lab", AcquiredBy = "Examiner", AcquisitionMethod = "Copy", ToolName = "t", ToolVersion = "1", SourceDeviceIdentifier = "d", File = new FormFile(new MemoryStream(bytes), 0, bytes.Length, "File", "evidence.txt") }, default);
        await service.StartAnalysisAsync(item.Id, "Analyst", default);
        await service.AddFindingAsync(new FindingInput { CaseId = item.Id, Title = "F", Description = "D", TechnicalDetails = "T", EvidenceReferences = item.Evidence.Single().Identifier, Analyst = "Analyst" }, default);
        await service.PrepareReportAsync(new ReportInput { CaseId = item.Id, ExecutiveSummary = "S", Methodology = "M", Conclusions = "C", Recommendations = "R", PreparedBy = "Analyst" }, default);
        await service.ReviewReportAsync(item.Id, "Reviewer", true, "Ok", default);
        var close = await service.CloseAsync(item.Id, "Reviewer", default);
        Assert.True(close.Success, close.Message);
        return item.Id;
    }

    [Fact]
    public async Task Retention_DisabledByDefault_NeverProposesDestruction()
    {
        var service = CreateService(retentionDays: 0);
        await CloseCaseAsync(service);

        var retention = new ForensicRetentionService(service, Options.Create(new ForensicStorageOptions { RetentionDays = 0 }));

        Assert.False(retention.Enabled);
        Assert.Empty(retention.GetCandidates(DateTimeOffset.UtcNow.AddYears(100)));
    }

    [Fact]
    public async Task Retention_ProposesOnlyClosedCasesAfterWindow_AndNeverDeletes()
    {
        var service = CreateService(retentionDays: 10);
        var caseId = await CloseCaseAsync(service);
        var retention = new ForensicRetentionService(service, Options.Create(new ForensicStorageOptions { RetentionDays = 10 }));
        var closedAt = service.Get(caseId)!.Closures.Last().ClosedAtUtc;

        Assert.Empty(retention.GetCandidates(closedAt.AddDays(9)));
        var candidates = retention.GetCandidates(closedAt.AddDays(11));
        var candidate = Assert.Single(candidates);
        Assert.Equal(caseId, candidate.CaseId);
        Assert.Equal(closedAt.AddDays(10), candidate.EligibleAtUtc);

        Assert.NotNull(service.Get(caseId));
        Assert.Single(service.Get(caseId)!.Evidence);
    }

    public void Dispose() { if (Directory.Exists(_root)) Directory.Delete(_root, true); }

    private sealed class RetentionEnvironment(string root) : IWebHostEnvironment
    {
        public string ApplicationName { get; set; } = "AtlasForense.Tests";
        public IFileProvider WebRootFileProvider { get; set; } = new PhysicalFileProvider(Directory.CreateDirectory(Path.Combine(root, "wwwroot")).FullName);
        public string WebRootPath { get; set; } = Path.Combine(root, "wwwroot");
        public string EnvironmentName { get; set; } = "Testing";
        public string ContentRootPath { get; set; } = root;
        public IFileProvider ContentRootFileProvider { get; set; } = new PhysicalFileProvider(root);
    }
}

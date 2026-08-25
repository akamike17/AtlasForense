using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AtlasForense.Models;
using AtlasForense.Forensics;

namespace AtlasForense.Services;

public sealed class JsonForensicCaseService : IForensicCaseService
{
    private const long MaxEvidenceBytes = 100 * 1024 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly string _databasePath;
    private readonly string _evidencePath;
    private readonly IReadOnlyList<IForensicAnalyzer> _analyzers;
    private List<ForensicCase> _cases;

    public JsonForensicCaseService(IWebHostEnvironment environment, IEnumerable<IForensicAnalyzer>? analyzers = null)
    {
        var dataPath = Path.Combine(environment.ContentRootPath, "App_Data");
        _evidencePath = Path.Combine(dataPath, "Evidence");
        _databasePath = Path.Combine(dataPath, "cases.json");
        _analyzers = analyzers?.ToList() ?? [];
        Directory.CreateDirectory(_evidencePath);
        _cases = Load();
    }

    public IReadOnlyList<ForensicCase> GetAll() => _cases.OrderByDescending(x => x.CreatedAtUtc).ToList();
    public ForensicCase? Get(Guid id) => _cases.FirstOrDefault(x => x.Id == id);

    public async Task<ForensicCase> CreateAsync(CreateCaseInput input, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var item = new ForensicCase
            {
                Folio = $"AF-{DateTime.UtcNow:yyyy}-{(_cases.Count + 1):D5}",
                Title = input.Title.Trim(), RequestingOrganization = input.RequestingOrganization.Trim(),
                LeadExaminer = input.LeadExaminer.Trim(), Scope = input.Scope.Trim()
            };
            AppendAudit(item, item.LeadExaminer, "CASE_CREATED", "Expediente creado en borrador.");
            _cases.Add(item);
            await SaveAsync(cancellationToken);
            return item;
        }
        finally { _gate.Release(); }
    }

    public Task<OperationResult> AuthorizeAsync(AuthorizeCaseInput input, CancellationToken token) => MutateAsync(input.CaseId, token, item =>
    {
        if (item.Status != CaseStatus.Draft) return OperationResult.Fail("Solo un expediente en borrador puede autorizarse.");
        item.Authorization = new AuthorizationRecord { Authority = input.Authority.Trim(), Reference = input.Reference.Trim(), ApprovedBy = input.ApprovedBy.Trim(), ApprovedAtUtc = DateTimeOffset.UtcNow, Limitations = input.Limitations.Trim() };
        item.Status = CaseStatus.Authorized;
        AppendAudit(item, input.ApprovedBy, "CASE_AUTHORIZED", $"Autorización {input.Reference} registrada.");
        return OperationResult.Ok("Etapa 1 completada: alcance y autorización registrados.");
    });

    public async Task<OperationResult> AcquireAsync(AcquireEvidenceInput input, CancellationToken cancellationToken)
    {
        if (input.File is null || input.File.Length == 0) return OperationResult.Fail("Selecciona un archivo de evidencia.");
        if (input.File.Length > MaxEvidenceBytes) return OperationResult.Fail("El archivo excede el límite de 100 MB.");
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var item = Get(input.CaseId);
            if (item is null) return OperationResult.Fail("Expediente no encontrado.");
            if (item.Status is not (CaseStatus.Authorized or CaseStatus.Acquiring)) return OperationResult.Fail("La adquisición requiere un expediente autorizado.");
            var evidenceId = Guid.NewGuid();
            var extension = Path.GetExtension(Path.GetFileName(input.File.FileName));
            if (extension.Length > 12) extension = string.Empty;
            var casePath = Path.Combine(_evidencePath, item.Id.ToString("N"));
            Directory.CreateDirectory(casePath);
            var storedName = $"{evidenceId:N}{extension.ToLowerInvariant()}";
            var finalPath = Path.Combine(casePath, storedName);
            var tempPath = finalPath + ".upload";
            try
            {
                await using (var source = input.File.OpenReadStream())
                await using (var destination = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, true))
                    await source.CopyToAsync(destination, cancellationToken);
                var hash = await HashFileAsync(tempPath, cancellationToken);
                File.Move(tempPath, finalPath);
                var evidence = new EvidenceItem
                {
                    Id = evidenceId, Identifier = $"{item.Folio}-E{item.Evidence.Count + 1:D3}", Description = input.Description.Trim(),
                    SourceType = input.SourceType.Trim(), SourceLocation = input.SourceLocation.Trim(), OriginalFileName = Path.GetFileName(input.File.FileName),
                    StoredFileName = storedName, SizeBytes = input.File.Length, Sha256 = hash, AcquiredAtUtc = DateTimeOffset.UtcNow,
                    AcquiredBy = input.AcquiredBy.Trim(), AcquisitionMethod = input.AcquisitionMethod.Trim(), Status = EvidenceStatus.Verified
                };
                evidence.ChainOfCustody.Add(new CustodyEvent { Action = "Adquisición y verificación SHA-256", PerformedBy = evidence.AcquiredBy, Location = evidence.SourceLocation, Notes = $"Hash {hash}" });
                item.Evidence.Add(evidence);
                item.Status = CaseStatus.Acquiring;
                AppendAudit(item, evidence.AcquiredBy, "EVIDENCE_ACQUIRED", $"{evidence.Identifier}; SHA-256 {hash}");
                await SaveAsync(cancellationToken);
                return OperationResult.Ok($"Evidencia {evidence.Identifier} preservada y verificada.");
            }
            finally { if (File.Exists(tempPath)) File.Delete(tempPath); }
        }
        finally { _gate.Release(); }
    }

    public Task<OperationResult> AddCustodyAsync(CustodyInput input, CancellationToken token) => MutateAsync(input.CaseId, token, item =>
    {
        var evidence = item.Evidence.FirstOrDefault(x => x.Id == input.EvidenceId);
        if (evidence is null) return OperationResult.Fail("Evidencia no encontrada.");
        evidence.ChainOfCustody.Add(new CustodyEvent { Action = input.Action.Trim(), PerformedBy = input.PerformedBy.Trim(), Location = input.Location.Trim(), Notes = input.Notes.Trim() });
        AppendAudit(item, input.PerformedBy, "CUSTODY_EVENT", $"{evidence.Identifier}: {input.Action}");
        return OperationResult.Ok("Movimiento añadido a la cadena de custodia.");
    });

    public Task<OperationResult> StartAnalysisAsync(Guid id, string actor, CancellationToken token) => MutateAsync(id, token, item =>
    {
        if (item.Status != CaseStatus.Acquiring || item.Evidence.Count == 0 || item.Evidence.Any(x => string.IsNullOrWhiteSpace(x.Sha256)))
            return OperationResult.Fail("La etapa 3 requiere al menos una evidencia adquirida y verificada.");
        item.Status = CaseStatus.Analyzing;
        AppendAudit(item, actor, "ANALYSIS_STARTED", "Conjunto de evidencia bloqueado para análisis.");
        return OperationResult.Ok("Etapa 2 completada. Análisis habilitado.");
    });

    public async Task<OperationResult> AnalyzeEvidenceAsync(Guid caseId, Guid evidenceId, string actor, CancellationToken token)
    {
        await _gate.WaitAsync(token);
        try
        {
            var item = Get(caseId);
            if (item is null) return OperationResult.Fail("Expediente no encontrado.");
            if (item.Status != CaseStatus.Analyzing) return OperationResult.Fail("El análisis automatizado requiere que la etapa 3 esté activa.");
            var evidence = item.Evidence.FirstOrDefault(x => x.Id == evidenceId);
            if (evidence is null) return OperationResult.Fail("Evidencia no encontrada.");
            var analyzer = _analyzers.FirstOrDefault(x => x.CanAnalyze(evidence));
            if (analyzer is null) return OperationResult.Fail("Aún no existe un analizador compatible con este tipo de evidencia.");

            var path = Path.Combine(_evidencePath, item.Id.ToString("N"), evidence.StoredFileName);
            if (!File.Exists(path)) return OperationResult.Fail("El archivo preservado no está disponible.");
            var currentHash = await HashFileAsync(path, token);
            if (!currentHash.Equals(evidence.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                AppendAudit(item, actor, "INTEGRITY_FAILURE", $"{evidence.Identifier}: hash almacenado {evidence.Sha256}; actual {currentHash}.");
                await SaveAsync(token);
                return OperationResult.Fail("La evidencia cambió desde su adquisición. El análisis fue bloqueado.");
            }

            var run = new AnalysisRun { EvidenceId = evidence.Id, AnalyzerId = analyzer.Id, AnalyzerVersion = analyzer.Version, StartedAtUtc = DateTimeOffset.UtcNow, NetworkBlocked = true, SampleExecuted = false };
            item.AnalysisRuns.Add(run);
            try
            {
                var output = await analyzer.AnalyzeAsync(new AnalyzerContext(item.Id, run.Id, evidence, path, token));
                item.Artifacts.RemoveAll(x => x.EvidenceId == evidence.Id && x.AnalysisRunId != run.Id && x.Name != "Manual");
                item.Artifacts.AddRange(output.Artifacts);
                MergeIndicators(item, output.Indicators);
                MergeEntities(item, output.Entities);
                item.Relationships.AddRange(output.Relationships);
                item.Events.AddRange(output.Events);
                run.Success = true;
                run.Summary = output.Summary;
                run.CompletedAtUtc = DateTimeOffset.UtcNow;
                AppendAudit(item, actor, "STATIC_ANALYSIS_COMPLETED", $"{evidence.Identifier}: {run.Summary}");
                await SaveAsync(token);
                return OperationResult.Ok(run.Summary);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidDataException)
            {
                run.Success = false;
                run.Error = exception.Message;
                run.CompletedAtUtc = DateTimeOffset.UtcNow;
                AppendAudit(item, actor, "STATIC_ANALYSIS_FAILED", $"{evidence.Identifier}: {exception.GetType().Name}");
                await SaveAsync(token);
                return OperationResult.Fail("El analizador no pudo procesar la evidencia; se conservó el registro de ejecución.");
            }
        }
        finally { _gate.Release(); }
    }

    public Task<OperationResult> AddFindingAsync(FindingInput input, CancellationToken token) => MutateAsync(input.CaseId, token, item =>
    {
        if (item.Status != CaseStatus.Analyzing) return OperationResult.Fail("Los hallazgos solo pueden registrarse durante el análisis.");
        item.Findings.Add(new Finding { Title = input.Title.Trim(), Severity = input.Severity, Description = input.Description.Trim(), TechnicalDetails = input.TechnicalDetails.Trim(), EvidenceReferences = input.EvidenceReferences.Trim(), EventTimeUtc = input.EventTimeUtc, Analyst = input.Analyst.Trim() });
        AppendAudit(item, input.Analyst, "FINDING_ADDED", $"Hallazgo: {input.Title} ({input.Severity}).");
        return OperationResult.Ok("Hallazgo correlacionado con la evidencia.");
    });

    public Task<OperationResult> PrepareReportAsync(ReportInput input, CancellationToken token) => MutateAsync(input.CaseId, token, item =>
    {
        if (item.Status != CaseStatus.Analyzing || item.Findings.Count == 0) return OperationResult.Fail("El informe requiere al menos un hallazgo documentado.");
        var report = new FinalReport { ExecutiveSummary = input.ExecutiveSummary.Trim(), Methodology = input.Methodology.Trim(), Conclusions = input.Conclusions.Trim(), Recommendations = input.Recommendations.Trim(), PreparedBy = input.PreparedBy.Trim(), PreparedAtUtc = DateTimeOffset.UtcNow };
        report.IntegrityHash = HashText($"{item.Folio}|{report.ExecutiveSummary}|{report.Methodology}|{report.Conclusions}|{report.Recommendations}|{report.PreparedBy}|{report.PreparedAtUtc:O}");
        item.Report = report;
        item.ReportReview = null;
        item.Status = CaseStatus.Reporting;
        AppendAudit(item, input.PreparedBy, "REPORT_PREPARED", $"Informe sellado: {report.IntegrityHash}");
        return OperationResult.Ok("Etapa 3 completada. Informe generado y sellado.");
    });

    public Task<OperationResult> ReviewReportAsync(Guid id, string reviewer, bool approve, string notes, CancellationToken token) => MutateAsync(id, token, item =>
    {
        if (item.Status != CaseStatus.Reporting || item.Report is null) return OperationResult.Fail("Solo puede revisarse un informe preparado y sellado.");
        reviewer = reviewer.Trim();
        if (string.IsNullOrWhiteSpace(reviewer)) return OperationResult.Fail("Identifica a la persona revisora.");
        if (reviewer.Equals(item.Report.PreparedBy, StringComparison.OrdinalIgnoreCase)) return OperationResult.Fail("La revisión debe realizarla una persona distinta de quien preparó el informe.");
        item.ReportReview = new ReportReview { ReviewedBy = reviewer, ReviewedAtUtc = DateTimeOffset.UtcNow, Approved = approve, Notes = notes.Trim(), ReviewedReportHash = item.Report.IntegrityHash };
        AppendAudit(item, reviewer, approve ? "REPORT_APPROVED" : "REPORT_REJECTED", $"Informe {item.Report.IntegrityHash}; {notes.Trim()}");
        if (!approve) item.Status = CaseStatus.Analyzing;
        return OperationResult.Ok(approve ? "Informe aprobado por revisión independiente." : "Informe devuelto al análisis con observaciones.");
    });

    public Task<OperationResult> CloseAsync(Guid id, string actor, CancellationToken token) => MutateAsync(id, token, item =>
    {
        if (item.Status != CaseStatus.Reporting || item.Report is null || item.ReportReview is null || !item.ReportReview.Approved || item.ReportReview.ReviewedReportHash != item.Report.IntegrityHash)
            return OperationResult.Fail("El cierre requiere un informe sellado y aprobado por revisión independiente.");
        item.Status = CaseStatus.Closed;
        item.Evidence.ForEach(x => x.Status = EvidenceStatus.Sealed);
        AppendAudit(item, actor, "CASE_CLOSED", "Expediente e inventario de evidencia sellados.");
        return OperationResult.Ok("Etapa 4 completada. Expediente cerrado y sellado.");
    });

    private async Task<OperationResult> MutateAsync(Guid id, CancellationToken token, Func<ForensicCase, OperationResult> change)
    {
        await _gate.WaitAsync(token);
        try
        {
            var item = Get(id);
            if (item is null) return OperationResult.Fail("Expediente no encontrado.");
            var result = change(item);
            if (result.Success) await SaveAsync(token);
            return result;
        }
        finally { _gate.Release(); }
    }

    private void AppendAudit(ForensicCase item, string actor, string action, string detail)
    {
        var previous = item.AuditTrail.LastOrDefault()?.EntryHash ?? "GENESIS";
        var entry = new AuditEntry { Sequence = item.AuditTrail.Count + 1, Actor = actor.Trim(), Action = action, Detail = detail, PreviousHash = previous };
        entry.EntryHash = HashText($"{item.Id}|{entry.Sequence}|{entry.OccurredAtUtc:O}|{entry.Actor}|{entry.Action}|{entry.Detail}|{previous}");
        item.AuditTrail.Add(entry);
    }

    private static void MergeIndicators(ForensicCase item, IEnumerable<CaseIndicator> indicators)
    {
        foreach (var indicator in indicators)
        {
            var existing = item.Indicators.FirstOrDefault(x => x.Type == indicator.Type && x.NormalizedValue.Equals(indicator.NormalizedValue, StringComparison.OrdinalIgnoreCase));
            if (existing is null) item.Indicators.Add(indicator);
            else foreach (var evidenceId in indicator.EvidenceIds.Where(id => !existing.EvidenceIds.Contains(id))) existing.EvidenceIds.Add(evidenceId);
        }
    }

    private static void MergeEntities(ForensicCase item, IEnumerable<CaseEntity> entities)
    {
        foreach (var entity in entities)
        {
            var existing = item.Entities.FirstOrDefault(x => x.Type == entity.Type && x.Value.Equals(entity.Value, StringComparison.OrdinalIgnoreCase));
            if (existing is null) item.Entities.Add(entity);
            else foreach (var evidenceId in entity.EvidenceIds.Where(id => !existing.EvidenceIds.Contains(id))) existing.EvidenceIds.Add(evidenceId);
        }
    }

    private List<ForensicCase> Load()
    {
        if (!File.Exists(_databasePath)) return [];
        try { return JsonSerializer.Deserialize<List<ForensicCase>>(File.ReadAllText(_databasePath), JsonOptions) ?? []; }
        catch (JsonException) { return []; }
    }

    private async Task SaveAsync(CancellationToken token)
    {
        var temp = _databasePath + ".tmp";
        await File.WriteAllTextAsync(temp, JsonSerializer.Serialize(_cases, JsonOptions), token);
        File.Move(temp, _databasePath, true);
    }

    private static async Task<string> HashFileAsync(string path, CancellationToken token)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, true);
        using var sha = SHA256.Create();
        return Convert.ToHexString(await sha.ComputeHashAsync(stream, token)).ToLowerInvariant();
    }

    private static string HashText(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
}

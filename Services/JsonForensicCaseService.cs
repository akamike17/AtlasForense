using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AtlasForense.Models;
using AtlasForense.Forensics;
using Microsoft.Data.Sqlite;

namespace AtlasForense.Services;

public sealed class JsonForensicCaseService : IForensicCaseService, IForensicDataMaintenance
{
    private const long MaxEvidenceBytes = 100 * 1024 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly string _legacyDatabasePath;
    private readonly string _databasePath;
    private readonly string _backupPath;
    private readonly string _evidencePath;
    private readonly IReadOnlyList<IForensicAnalyzer> _analyzers;
    private readonly Dictionary<Guid, long> _rowVersions = [];
    private List<ForensicCase> _cases;

    static JsonForensicCaseService()
    {
        SQLitePCL.raw.SetProvider(OperatingSystem.IsWindows()
            ? new SQLitePCL.SQLite3Provider_winsqlite3()
            : new SQLitePCL.SQLite3Provider_sqlite3());
        SQLitePCL.raw.FreezeProvider();
    }

    public JsonForensicCaseService(IWebHostEnvironment environment, IEnumerable<IForensicAnalyzer>? analyzers = null)
    {
        var dataPath = Path.Combine(environment.ContentRootPath, "App_Data");
        _evidencePath = Path.Combine(dataPath, "Evidence");
        _legacyDatabasePath = Path.Combine(dataPath, "cases.json");
        _databasePath = Path.Combine(dataPath, "atlas-forense.db");
        _backupPath = Path.Combine(dataPath, "Backups");
        _analyzers = analyzers?.ToList() ?? [];
        Directory.CreateDirectory(dataPath);
        Directory.CreateDirectory(_evidencePath);
        Directory.CreateDirectory(_backupPath);
        InitializeDatabase();
        _cases = Load();
        ImportLegacyDataIfNeeded();
    }

    public IReadOnlyList<ForensicCase> GetAll() => _cases.OrderByDescending(x => x.CreatedAtUtc).ToList();
    public ForensicCase? Get(Guid id) => _cases.FirstOrDefault(x => x.Id == id);

    public async Task<DataIntegrityResult> VerifyAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var connection = OpenConnection();
            await using var command = connection.CreateCommand();
            command.CommandText = "PRAGMA quick_check;";
            var databaseResult = Convert.ToString(await command.ExecuteScalarAsync(cancellationToken));
            if (!string.Equals(databaseResult, "ok", StringComparison.OrdinalIgnoreCase))
                return new(false, $"SQLite informó: {databaseResult}", _cases.Count);
            foreach (var item in _cases)
            {
                var previous = "GENESIS";
                long expectedSequence = 1;
                foreach (var entry in item.AuditTrail.OrderBy(x => x.Sequence))
                {
                    var expectedHash = HashText($"{item.Id}|{entry.Sequence}|{entry.OccurredAtUtc:O}|{entry.Actor}|{entry.Action}|{entry.Detail}|{previous}");
                    if (entry.Sequence != expectedSequence || entry.PreviousHash != previous || !entry.EntryHash.Equals(expectedHash, StringComparison.OrdinalIgnoreCase))
                        return new(false, $"Cadena de auditoría inválida en {item.Folio}, secuencia {entry.Sequence}.", _cases.Count);
                    previous = entry.EntryHash;
                    expectedSequence++;
                }
            }
            return new(true, "Base SQLite y cadenas de auditoría verificadas.", _cases.Count);
        }
        finally { _gate.Release(); }
    }

    public async Task<BackupResult> CreateBackupAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var fileName = $"atlas-forense-{DateTime.UtcNow:yyyyMMddTHHmmssfffZ}-{Guid.NewGuid():N}.db";
            var path = Path.Combine(_backupPath, fileName);
            var valid = false;
            await using (var source = OpenConnection())
            await using (var destination = new SqliteConnection($"Data Source={path};Mode=ReadWriteCreate;Pooling=False"))
            {
                await destination.OpenAsync(cancellationToken);
                source.BackupDatabase(destination);
                await using var check = destination.CreateCommand();
                check.CommandText = "PRAGMA quick_check;";
                valid = string.Equals(Convert.ToString(await check.ExecuteScalarAsync(cancellationToken)), "ok", StringComparison.OrdinalIgnoreCase);
            }
            if (!valid)
            {
                File.Delete(path);
                return new(false, string.Empty, string.Empty, _cases.Count, "La copia no superó la verificación de integridad.");
            }
            var hash = await HashFileAsync(path, cancellationToken);
            return new(true, fileName, hash, _cases.Count, "Respaldo SQLite creado y verificado.");
        }
        finally { _gate.Release(); }
    }

    public async Task<DataIntegrityResult> RestoreBackupAsync(string backupFileName, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(backupFileName) || Path.GetFileName(backupFileName) != backupFileName)
            return new(false, "Nombre de respaldo inválido.", _cases.Count);
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var sourcePath = Path.Combine(_backupPath, backupFileName);
            if (!File.Exists(sourcePath)) return new(false, "Respaldo no encontrado.", _cases.Count);
            var restorePath = _databasePath + ".restore";
            try
            {
                await using (var source = new SqliteConnection($"Data Source={sourcePath};Mode=ReadOnly;Pooling=False"))
                await using (var destination = new SqliteConnection($"Data Source={restorePath};Mode=ReadWriteCreate;Pooling=False"))
                {
                    await source.OpenAsync(cancellationToken);
                    await destination.OpenAsync(cancellationToken);
                    await using var check = source.CreateCommand();
                    check.CommandText = "PRAGMA quick_check;";
                    if (!string.Equals(Convert.ToString(await check.ExecuteScalarAsync(cancellationToken)), "ok", StringComparison.OrdinalIgnoreCase))
                        return new(false, "El respaldo está dañado y no fue restaurado.", _cases.Count);
                    source.BackupDatabase(destination);
                }
                File.Move(restorePath, _databasePath, true);
                _rowVersions.Clear();
                _cases = Load();
                return new(true, "Respaldo restaurado y recargado.", _cases.Count);
            }
            finally { if (File.Exists(restorePath)) File.Delete(restorePath); }
        }
        finally { _gate.Release(); }
    }

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

    private void InitializeDatabase()
    {
        using var connection = OpenConnection();
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS SchemaMigrations (
                Version INTEGER NOT NULL PRIMARY KEY,
                AppliedAtUtc TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS Cases (
                Id TEXT NOT NULL PRIMARY KEY,
                Folio TEXT NOT NULL UNIQUE,
                Status INTEGER NOT NULL,
                CreatedAtUtc TEXT NOT NULL,
                DocumentJson TEXT NOT NULL,
                RowVersion INTEGER NOT NULL DEFAULT 1 CHECK (RowVersion > 0)
            );
            CREATE TABLE IF NOT EXISTS EvidenceItems (
                Id TEXT NOT NULL PRIMARY KEY,
                CaseId TEXT NOT NULL,
                Identifier TEXT NOT NULL,
                Sha256 TEXT NOT NULL CHECK (length(Sha256) = 64),
                StoredFileName TEXT NOT NULL,
                Classification INTEGER NOT NULL DEFAULT 0,
                UNIQUE (CaseId, Identifier),
                FOREIGN KEY (CaseId) REFERENCES Cases(Id) ON DELETE RESTRICT
            );
            CREATE TABLE IF NOT EXISTS AuditEntries (
                CaseId TEXT NOT NULL,
                Sequence INTEGER NOT NULL CHECK (Sequence > 0),
                EntryHash TEXT NOT NULL CHECK (length(EntryHash) = 64),
                PreviousHash TEXT NOT NULL,
                OccurredAtUtc TEXT NOT NULL,
                PRIMARY KEY (CaseId, Sequence),
                FOREIGN KEY (CaseId) REFERENCES Cases(Id) ON DELETE RESTRICT
            );
            INSERT OR IGNORE INTO SchemaMigrations (Version, AppliedAtUtc)
            VALUES (1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
            """;
        command.ExecuteNonQuery();
        transaction.Commit();
    }

    private List<ForensicCase> Load()
    {
        var result = new List<ForensicCase>();
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT Id, DocumentJson, RowVersion FROM Cases ORDER BY CreatedAtUtc;";
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var item = JsonSerializer.Deserialize<ForensicCase>(reader.GetString(1), JsonOptions);
            if (item is null) throw new InvalidDataException($"El expediente {reader.GetString(0)} no puede deserializarse.");
            result.Add(item);
            _rowVersions[item.Id] = reader.GetInt64(2);
        }
        return result;
    }

    private void ImportLegacyDataIfNeeded()
    {
        if (_cases.Count != 0 || !File.Exists(_legacyDatabasePath)) return;
        List<ForensicCase> legacy;
        try
        {
            legacy = JsonSerializer.Deserialize<List<ForensicCase>>(File.ReadAllText(_legacyDatabasePath), JsonOptions) ?? [];
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("El archivo cases.json existente no es válido; no se modificó ni importó.", exception);
        }
        if (legacy.Count == 0) return;
        _cases = legacy;
        SaveAsync(CancellationToken.None).GetAwaiter().GetResult();
    }

    private async Task SaveAsync(CancellationToken token)
    {
        await using var connection = OpenConnection();
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(token);
        foreach (var item in _cases)
        {
            var json = JsonSerializer.Serialize(item, JsonOptions);
            if (_rowVersions.TryGetValue(item.Id, out var version))
            {
                await using var update = connection.CreateCommand();
                update.Transaction = transaction;
                update.CommandText = """
                    UPDATE Cases SET Folio = $folio, Status = $status, CreatedAtUtc = $created,
                        DocumentJson = $json, RowVersion = RowVersion + 1
                    WHERE Id = $id AND RowVersion = $version;
                    """;
                AddCaseParameters(update, item, json);
                update.Parameters.AddWithValue("$version", version);
                if (await update.ExecuteNonQueryAsync(token) != 1)
                    throw new InvalidOperationException($"Conflicto de concurrencia al guardar el expediente {item.Folio}.");
                _rowVersions[item.Id] = version + 1;
            }
            else
            {
                await using var insert = connection.CreateCommand();
                insert.Transaction = transaction;
                insert.CommandText = """
                    INSERT INTO Cases (Id, Folio, Status, CreatedAtUtc, DocumentJson, RowVersion)
                    VALUES ($id, $folio, $status, $created, $json, 1);
                    """;
                AddCaseParameters(insert, item, json);
                await insert.ExecuteNonQueryAsync(token);
                _rowVersions[item.Id] = 1;
            }

            await ReplaceIntegrityRowsAsync(connection, transaction, item, token);
        }
        await transaction.CommitAsync(token);
    }

    private SqliteConnection OpenConnection()
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = _databasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private,
            Pooling = false
        }.ToString());
        connection.Open();
        using var pragma = connection.CreateCommand();
        pragma.CommandText = "PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;";
        pragma.ExecuteNonQuery();
        return connection;
    }

    private static void AddCaseParameters(SqliteCommand command, ForensicCase item, string json)
    {
        command.Parameters.AddWithValue("$id", item.Id.ToString("D"));
        command.Parameters.AddWithValue("$folio", item.Folio);
        command.Parameters.AddWithValue("$status", (int)item.Status);
        command.Parameters.AddWithValue("$created", item.CreatedAtUtc.ToUniversalTime().ToString("O"));
        command.Parameters.AddWithValue("$json", json);
    }

    private static async Task ReplaceIntegrityRowsAsync(SqliteConnection connection, SqliteTransaction transaction, ForensicCase item, CancellationToken token)
    {
        foreach (var table in new[] { "EvidenceItems", "AuditEntries" })
        {
            await using var delete = connection.CreateCommand();
            delete.Transaction = transaction;
            delete.CommandText = $"DELETE FROM {table} WHERE CaseId = $caseId;";
            delete.Parameters.AddWithValue("$caseId", item.Id.ToString("D"));
            await delete.ExecuteNonQueryAsync(token);
        }
        foreach (var evidence in item.Evidence)
        {
            await using var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = "INSERT INTO EvidenceItems (Id, CaseId, Identifier, Sha256, StoredFileName) VALUES ($id, $caseId, $identifier, $sha256, $stored);";
            insert.Parameters.AddWithValue("$id", evidence.Id.ToString("D"));
            insert.Parameters.AddWithValue("$caseId", item.Id.ToString("D"));
            insert.Parameters.AddWithValue("$identifier", evidence.Identifier);
            insert.Parameters.AddWithValue("$sha256", evidence.Sha256);
            insert.Parameters.AddWithValue("$stored", evidence.StoredFileName);
            await insert.ExecuteNonQueryAsync(token);
        }
        foreach (var audit in item.AuditTrail)
        {
            await using var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = "INSERT INTO AuditEntries (CaseId, Sequence, EntryHash, PreviousHash, OccurredAtUtc) VALUES ($caseId, $sequence, $hash, $previous, $occurred);";
            insert.Parameters.AddWithValue("$caseId", item.Id.ToString("D"));
            insert.Parameters.AddWithValue("$sequence", audit.Sequence);
            insert.Parameters.AddWithValue("$hash", audit.EntryHash);
            insert.Parameters.AddWithValue("$previous", audit.PreviousHash);
            insert.Parameters.AddWithValue("$occurred", audit.OccurredAtUtc.ToUniversalTime().ToString("O"));
            await insert.ExecuteNonQueryAsync(token);
        }
    }

    private static async Task<string> HashFileAsync(string path, CancellationToken token)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, true);
        using var sha = SHA256.Create();
        return Convert.ToHexString(await sha.ComputeHashAsync(stream, token)).ToLowerInvariant();
    }

    private static string HashText(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
}

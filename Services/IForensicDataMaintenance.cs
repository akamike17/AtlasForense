namespace AtlasForense.Services;

public interface IForensicDataMaintenance
{
    Task<DataIntegrityResult> VerifyAsync(CancellationToken cancellationToken);
    Task<BackupResult> CreateBackupAsync(CancellationToken cancellationToken);
    Task<DataIntegrityResult> RestoreBackupAsync(string backupFileName, CancellationToken cancellationToken);
}

public sealed record DataIntegrityResult(bool Success, string Message, int CaseCount);

public sealed record BackupResult(bool Success, string FileName, string Sha256, int CaseCount, string Message);

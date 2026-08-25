using System.ComponentModel.DataAnnotations;

namespace AtlasForense.Models;

public enum CaseStatus { Draft, Authorized, Acquiring, Analyzing, Reporting, Closed }
public enum EvidenceStatus { Registered, Acquired, Verified, Sealed }
public enum FindingSeverity { Informational, Low, Medium, High, Critical }

public sealed class ForensicCase
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Folio { get; set; } = string.Empty;
    [Required, StringLength(160)] public string Title { get; set; } = string.Empty;
    [Required, StringLength(120)] public string RequestingOrganization { get; set; } = string.Empty;
    [Required, StringLength(120)] public string LeadExaminer { get; set; } = string.Empty;
    [Required, StringLength(1000)] public string Scope { get; set; } = string.Empty;
    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    public CaseStatus Status { get; set; } = CaseStatus.Draft;
    public AuthorizationRecord? Authorization { get; set; }
    public List<EvidenceItem> Evidence { get; set; } = [];
    public List<Finding> Findings { get; set; } = [];
    public FinalReport? Report { get; set; }
    public List<AuditEntry> AuditTrail { get; set; } = [];
}

public sealed class AuthorizationRecord
{
    public string Authority { get; set; } = string.Empty;
    public string Reference { get; set; } = string.Empty;
    public string ApprovedBy { get; set; } = string.Empty;
    public DateTimeOffset ApprovedAtUtc { get; set; }
    public string Limitations { get; set; } = string.Empty;
}

public sealed class EvidenceItem
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Identifier { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string SourceType { get; set; } = string.Empty;
    public string SourceLocation { get; set; } = string.Empty;
    public string OriginalFileName { get; set; } = string.Empty;
    public string StoredFileName { get; set; } = string.Empty;
    public long SizeBytes { get; set; }
    public string Sha256 { get; set; } = string.Empty;
    public DateTimeOffset AcquiredAtUtc { get; set; }
    public string AcquiredBy { get; set; } = string.Empty;
    public string AcquisitionMethod { get; set; } = string.Empty;
    public EvidenceStatus Status { get; set; }
    public List<CustodyEvent> ChainOfCustody { get; set; } = [];
}

public sealed class CustodyEvent
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public DateTimeOffset OccurredAtUtc { get; set; } = DateTimeOffset.UtcNow;
    public string Action { get; set; } = string.Empty;
    public string PerformedBy { get; set; } = string.Empty;
    public string Location { get; set; } = string.Empty;
    public string Notes { get; set; } = string.Empty;
}

public sealed class Finding
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Title { get; set; } = string.Empty;
    public FindingSeverity Severity { get; set; }
    public string Description { get; set; } = string.Empty;
    public string TechnicalDetails { get; set; } = string.Empty;
    public string EvidenceReferences { get; set; } = string.Empty;
    public DateTimeOffset? EventTimeUtc { get; set; }
    public string Analyst { get; set; } = string.Empty;
    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
}

public sealed class FinalReport
{
    public string ExecutiveSummary { get; set; } = string.Empty;
    public string Methodology { get; set; } = string.Empty;
    public string Conclusions { get; set; } = string.Empty;
    public string Recommendations { get; set; } = string.Empty;
    public string PreparedBy { get; set; } = string.Empty;
    public DateTimeOffset PreparedAtUtc { get; set; }
    public string IntegrityHash { get; set; } = string.Empty;
}

public sealed class AuditEntry
{
    public long Sequence { get; set; }
    public DateTimeOffset OccurredAtUtc { get; set; } = DateTimeOffset.UtcNow;
    public string Actor { get; set; } = string.Empty;
    public string Action { get; set; } = string.Empty;
    public string Detail { get; set; } = string.Empty;
    public string PreviousHash { get; set; } = string.Empty;
    public string EntryHash { get; set; } = string.Empty;
}

public sealed record OperationResult(bool Success, string Message)
{
    public static OperationResult Ok(string message) => new(true, message);
    public static OperationResult Fail(string message) => new(false, message);
}

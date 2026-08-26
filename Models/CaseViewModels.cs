using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace AtlasForense.Models;

public sealed class CreateCaseInput
{
    [Required, StringLength(160)] public string Title { get; set; } = string.Empty;
    [Required, StringLength(120)] public string RequestingOrganization { get; set; } = string.Empty;
    [BindNever, StringLength(120)] public string LeadExaminer { get; set; } = string.Empty;
    [BindNever] public Guid ActorUserId { get; set; }
    [Required, StringLength(1000)] public string Scope { get; set; } = string.Empty;
}

public sealed class AuthorizeCaseInput
{
    public Guid CaseId { get; set; }
    [Required, StringLength(160)] public string Authority { get; set; } = string.Empty;
    [Required, StringLength(160)] public string Reference { get; set; } = string.Empty;
    [BindNever, StringLength(120)] public string ApprovedBy { get; set; } = string.Empty;
    [StringLength(1000)] public string Limitations { get; set; } = string.Empty;
}

public sealed class AcquireEvidenceInput
{
    public Guid CaseId { get; set; }
    [Required, StringLength(500)] public string Description { get; set; } = string.Empty;
    [Required, StringLength(80)] public string SourceType { get; set; } = string.Empty;
    [Required, StringLength(300)] public string SourceLocation { get; set; } = string.Empty;
    [BindNever, StringLength(120)] public string AcquiredBy { get; set; } = string.Empty;
    [Required, StringLength(200)] public string AcquisitionMethod { get; set; } = string.Empty;
    [Required, StringLength(120)] public string ToolName { get; set; } = string.Empty;
    [Required, StringLength(80)] public string ToolVersion { get; set; } = string.Empty;
    [StringLength(200)] public string SourceDeviceIdentifier { get; set; } = string.Empty;
    [StringLength(1000)] public string AcquisitionLimitations { get; set; } = string.Empty;
    [RegularExpression("^[A-Fa-f0-9]{64}$", ErrorMessage = "El SHA-256 esperado debe contener 64 caracteres hexadecimales.")]
    public string? ExpectedSha256 { get; set; }
    [Required] public IFormFile? File { get; set; }
}

public sealed class CustodyInput
{
    public Guid CaseId { get; set; }
    public Guid EvidenceId { get; set; }
    [Required, StringLength(120)] public string Action { get; set; } = string.Empty;
    [BindNever, StringLength(120)] public string PerformedBy { get; set; } = string.Empty;
    [Required, StringLength(200)] public string Location { get; set; } = string.Empty;
    [StringLength(500)] public string Notes { get; set; } = string.Empty;
}

public sealed class FindingInput
{
    public Guid CaseId { get; set; }
    [Required, StringLength(180)] public string Title { get; set; } = string.Empty;
    public FindingSeverity Severity { get; set; }
    [Required, StringLength(2000)] public string Description { get; set; } = string.Empty;
    [Required, StringLength(5000)] public string TechnicalDetails { get; set; } = string.Empty;
    [Required, StringLength(1000)] public string EvidenceReferences { get; set; } = string.Empty;
    public DateTimeOffset? EventTimeUtc { get; set; }
    [BindNever, StringLength(120)] public string Analyst { get; set; } = string.Empty;
}

public sealed class ReportInput
{
    public Guid CaseId { get; set; }
    [Required, StringLength(4000)] public string ExecutiveSummary { get; set; } = string.Empty;
    [Required, StringLength(4000)] public string Methodology { get; set; } = string.Empty;
    [Required, StringLength(4000)] public string Conclusions { get; set; } = string.Empty;
    [Required, StringLength(4000)] public string Recommendations { get; set; } = string.Empty;
    [BindNever, StringLength(120)] public string PreparedBy { get; set; } = string.Empty;
}

public sealed class CaseAssignmentInput
{
    public Guid CaseId { get; set; }
    public Guid UserId { get; set; }
    public ForensicRole Role { get; set; }
}

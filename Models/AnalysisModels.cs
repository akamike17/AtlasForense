namespace AtlasForense.Models;

public enum ArtifactKind { Metadata, Url, Domain, IpAddress, Email, FileHash, NetworkEndpoint, ScriptFunction, String, SecretReference, Capability }
public enum ConfidenceLevel { Observed, Confirmed, Corroborated, Inferred }
public enum IndicatorType { Url, Domain, IpAddress, Email, Hash, FileName, RegistryKey, Mutex, Other }

public sealed class AnalysisRun
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid EvidenceId { get; set; }
    public string AnalyzerId { get; set; } = string.Empty;
    public string AnalyzerVersion { get; set; } = string.Empty;
    public DateTimeOffset StartedAtUtc { get; set; }
    public DateTimeOffset CompletedAtUtc { get; set; }
    public bool NetworkBlocked { get; set; } = true;
    public bool SampleExecuted { get; set; }
    public bool Success { get; set; }
    public string Summary { get; set; } = string.Empty;
    public string Error { get; set; } = string.Empty;
}

public sealed class AnalysisArtifact
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid EvidenceId { get; set; }
    public Guid AnalysisRunId { get; set; }
    public ArtifactKind Kind { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Value { get; set; } = string.Empty;
    public string Context { get; set; } = string.Empty;
    public long? Offset { get; set; }
    public ConfidenceLevel Confidence { get; set; }
    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
}

public sealed class TimelineEvent
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid? EvidenceId { get; set; }
    public DateTimeOffset OccurredAtUtc { get; set; }
    public string Category { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Source { get; set; } = string.Empty;
    public ConfidenceLevel Confidence { get; set; }
}

public sealed class CaseEntity
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Type { get; set; } = string.Empty;
    public string Value { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public ConfidenceLevel Confidence { get; set; }
    public List<Guid> EvidenceIds { get; set; } = [];
}

public sealed class CaseRelationship
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid SourceEntityId { get; set; }
    public Guid TargetEntityId { get; set; }
    public string RelationshipType { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public ConfidenceLevel Confidence { get; set; }
    public List<Guid> EvidenceIds { get; set; } = [];
}

public sealed class CaseIndicator
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public IndicatorType Type { get; set; }
    public string Value { get; set; } = string.Empty;
    public string NormalizedValue { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public ConfidenceLevel Confidence { get; set; }
    public bool IsMalicious { get; set; }
    public List<Guid> EvidenceIds { get; set; } = [];
}

public sealed class CaseNote
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Title { get; set; } = string.Empty;
    public string Content { get; set; } = string.Empty;
    public string Author { get; set; } = string.Empty;
    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    public bool IncludeInReport { get; set; }
    public int ReportOrder { get; set; }
}

public sealed class AnalyzerOutput
{
    public List<AnalysisArtifact> Artifacts { get; } = [];
    public List<CaseIndicator> Indicators { get; } = [];
    public List<CaseEntity> Entities { get; } = [];
    public List<CaseRelationship> Relationships { get; } = [];
    public List<TimelineEvent> Events { get; } = [];
    public string Summary { get; set; } = string.Empty;
}

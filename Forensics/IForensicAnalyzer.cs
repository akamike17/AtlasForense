using AtlasForense.Models;

namespace AtlasForense.Forensics;

public sealed record AnalyzerContext(Guid CaseId, Guid AnalysisRunId, EvidenceItem Evidence, string FilePath, CancellationToken CancellationToken);

public interface IForensicAnalyzer
{
    string Id { get; }
    string Version { get; }
    bool CanAnalyze(EvidenceItem evidence);
    Task<AnalyzerOutput> AnalyzeAsync(AnalyzerContext context);
}

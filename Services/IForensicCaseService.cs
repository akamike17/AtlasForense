using AtlasForense.Models;

namespace AtlasForense.Services;

public interface IForensicCaseService
{
    IReadOnlyList<ForensicCase> GetAll();
    ForensicCase? Get(Guid id);
    Task<ForensicCase> CreateAsync(CreateCaseInput input, CancellationToken cancellationToken);
    Task<OperationResult> AuthorizeAsync(AuthorizeCaseInput input, CancellationToken cancellationToken);
    Task<OperationResult> AcquireAsync(AcquireEvidenceInput input, CancellationToken cancellationToken);
    Task<OperationResult> AddCustodyAsync(CustodyInput input, CancellationToken cancellationToken);
    Task<OperationResult> StartAnalysisAsync(Guid id, string actor, CancellationToken cancellationToken);
    Task<OperationResult> AnalyzeEvidenceAsync(Guid caseId, Guid evidenceId, string actor, CancellationToken cancellationToken);
    Task<OperationResult> AddFindingAsync(FindingInput input, CancellationToken cancellationToken);
    Task<OperationResult> PrepareReportAsync(ReportInput input, CancellationToken cancellationToken);
    Task<OperationResult> ReviewReportAsync(Guid id, string reviewer, bool approve, string notes, CancellationToken cancellationToken);
    Task<OperationResult> CloseAsync(Guid id, string actor, CancellationToken cancellationToken);
}

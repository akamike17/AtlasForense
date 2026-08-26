using AtlasForense.Models;
using Microsoft.Extensions.Options;

namespace AtlasForense.Services;

public sealed record RetentionCandidate(Guid CaseId, string Folio, DateTimeOffset ClosedAtUtc, DateTimeOffset EligibleAtUtc);

public interface IForensicRetention
{
    bool Enabled { get; }
    IReadOnlyList<RetentionCandidate> GetCandidates(DateTimeOffset nowUtc);
}

// Retención automatizada en modo seguro: identifica expedientes cerrados que
// superan la política configurada y los propone para revisión/archivado. Nunca
// elimina evidencia ni expedientes: la destrucción de evidencia forense es una
// decisión humana sujeta a obligaciones legales y de cadena de custodia.
public sealed class ForensicRetentionService(IForensicCaseService cases, IOptions<ForensicStorageOptions> options) : IForensicRetention
{
    private readonly ForensicStorageOptions _options = options.Value;

    public bool Enabled => _options.RetentionDays > 0;

    public IReadOnlyList<RetentionCandidate> GetCandidates(DateTimeOffset nowUtc)
    {
        if (!Enabled) return [];
        var window = TimeSpan.FromDays(_options.RetentionDays);
        return cases.GetAll()
            .Where(item => item.Status == CaseStatus.Closed)
            .Select(item => (Item: item, Closure: item.Closures.LastOrDefault()))
            .Where(x => x.Closure is not null && x.Closure.ReopenedAtUtc is null)
            .Select(x => new RetentionCandidate(x.Item.Id, x.Item.Folio, x.Closure!.ClosedAtUtc, x.Closure.ClosedAtUtc + window))
            .Where(candidate => nowUtc >= candidate.EligibleAtUtc)
            .OrderBy(candidate => candidate.EligibleAtUtc)
            .ToList();
    }
}

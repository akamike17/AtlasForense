namespace AtlasForense.Services;

public interface IArchiveSafetyInspector
{
    Task<ArchiveSafetyResult> InspectZipAsync(string path, CancellationToken cancellationToken);
}

public sealed record ArchiveSafetyResult(bool Safe, string Message, int EntryCount, long ExpandedBytes);

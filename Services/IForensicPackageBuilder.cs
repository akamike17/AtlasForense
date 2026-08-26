using AtlasForense.Models;

namespace AtlasForense.Services;

public interface IForensicPackageBuilder
{
    Task<ForensicPackageResult> BuildAsync(ForensicCase item, CancellationToken cancellationToken);
}

public interface IForensicPackageSigner
{
    bool IsAvailable { get; }
    PackageSignature Sign(ReadOnlySpan<byte> canonicalManifest);
}

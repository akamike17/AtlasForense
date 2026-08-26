namespace AtlasForense.Models;

public sealed record PackageManifestEntry(string Path, long SizeBytes, string Sha256, string Classification);

public sealed record ForensicPackageResult(bool Success, string Message, string FileName, string Path, string Sha256, string CertificateSha256);

public sealed record PackageSignature(byte[] Signature, byte[] PublicCertificate, string Algorithm, string CertificateSha256);

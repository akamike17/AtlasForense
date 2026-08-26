using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using AtlasForense.Models;

namespace AtlasForense.Services;

public sealed class SignedForensicPackageBuilder : IForensicPackageBuilder
{
    private static readonly DateTimeOffset DeterministicZipTime = new(2000, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private readonly string _evidenceRoot;
    private readonly string _exportRoot;
    private readonly IForensicReportBuilder _reports;
    private readonly IForensicPackageSigner _signer;
    private readonly IEvidenceCipher _cipher;

    public SignedForensicPackageBuilder(IWebHostEnvironment environment, IForensicReportBuilder reports, IForensicPackageSigner signer, IEvidenceCipher? evidenceCipher = null)
    {
        var data = Path.Combine(environment.ContentRootPath, "App_Data");
        _evidenceRoot = Path.Combine(data, "Evidence"); _exportRoot = Path.Combine(data, "Exports");
        Directory.CreateDirectory(_exportRoot); _reports = reports; _signer = signer;
        _cipher = evidenceCipher ?? AesGcmEvidenceCipher.Ephemeral();
    }

    public async Task<ForensicPackageResult> BuildAsync(ForensicCase item, CancellationToken cancellationToken)
    {
        if (item.Report is null || item.ReportReview?.Approved != true || item.ReportReview.ReviewedReportHash != item.Report.IntegrityHash)
            return new(false, "El paquete requiere un informe aprobado ligado al hash vigente.", string.Empty, string.Empty, string.Empty, string.Empty);
        if (!_signer.IsAvailable) return new(false, "No hay un certificado de firma configurado.", string.Empty, string.Empty, string.Empty, string.Empty);
        var report = _reports.BuildMarkdown(item);
        var files = new List<(string ArchivePath, string SourcePath, byte[]? Content, PackageManifestEntry Manifest)>();
        var reportBytes = Encoding.UTF8.GetBytes(report.Content);
        files.Add(("report/report.md", string.Empty, reportBytes, new("report/report.md", reportBytes.Length, Hash(reportBytes), "approved-report")));
        foreach (var evidence in item.Evidence.OrderBy(x => x.Identifier, StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var source = Path.Combine(_evidenceRoot, item.Id.ToString("N"), evidence.StoredFileName);
            if (!File.Exists(source)) return new(false, $"Falta la evidencia {evidence.Identifier}.", string.Empty, string.Empty, string.Empty, string.Empty);
            string hash;
            try { hash = _cipher.IsEnvelope(source) ? await _cipher.ComputePlaintextSha256Async(source, cancellationToken) : await HashFileAsync(source, cancellationToken); }
            catch (InvalidDataException) { return new(false, $"La evidencia {evidence.Identifier} no pudo descifrarse; posible alteración.", string.Empty, string.Empty, string.Empty, string.Empty); }
            if (!hash.Equals(evidence.Sha256, StringComparison.OrdinalIgnoreCase)) return new(false, $"La evidencia {evidence.Identifier} no superó SHA-256.", string.Empty, string.Empty, string.Empty, string.Empty);
            var archivePath = $"evidence/{evidence.Identifier}/{SafeName(evidence.OriginalFileName)}";
            if (_cipher.IsEnvelope(source))
            {
                var decrypted = Path.Combine(_exportRoot, $"{Guid.NewGuid():N}.plain");
                await _cipher.DecryptAsync(source, decrypted, cancellationToken);
                files.Add((archivePath, decrypted, null, new(archivePath, evidence.SizeBytes, hash, "original-evidence")));
            }
            else files.Add((archivePath, source, null, new(archivePath, evidence.SizeBytes, hash, "original-evidence")));
        }
        var canonicalManifest = BuildCanonicalManifest(item, files.Select(x => x.Manifest));
        var signature = _signer.Sign(canonicalManifest);
        if (!VerifySignature(canonicalManifest, signature)) return new(false, "El proveedor produjo una firma no verificable.", string.Empty, string.Empty, string.Empty, string.Empty);
        var fileName = $"{SafeName(item.Folio)}-v{item.Report.Version:D3}.afpkg";
        var path = Path.Combine(_exportRoot, $"{Guid.NewGuid():N}.afpkg");
        try
        {
            await using (var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 131072, FileOptions.Asynchronous | FileOptions.SequentialScan))
            using (var archive = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
            {
                foreach (var file in files.OrderBy(x => x.ArchivePath, StringComparer.Ordinal))
                {
                    var entry = CreateEntry(archive, file.ArchivePath);
                    await using var target = entry.Open();
                    if (file.Content is not null) await target.WriteAsync(file.Content, cancellationToken);
                    else await using (var source = new FileStream(file.SourcePath, FileMode.Open, FileAccess.Read, FileShare.Read, 131072, FileOptions.Asynchronous | FileOptions.SequentialScan)) await source.CopyToAsync(target, cancellationToken);
                }
                await WriteEntryAsync(archive, "manifest.json", canonicalManifest, cancellationToken);
                await WriteEntryAsync(archive, "signature.bin", signature.Signature, cancellationToken);
                await WriteEntryAsync(archive, "signer.cer", signature.PublicCertificate, cancellationToken);
                await WriteEntryAsync(archive, "signature-algorithm.txt", Encoding.ASCII.GetBytes(signature.Algorithm), cancellationToken);
            }
            if (!await VerifyWrittenPackageAsync(path, files.Select(x => x.Manifest), cancellationToken))
            {
                File.Delete(path);
                DeleteDecryptedTemps(files);
                return new(false, "El paquete escrito no coincide con el manifiesto; fue descartado.", string.Empty, string.Empty, string.Empty, string.Empty);
            }
            var packageHash = await HashFileAsync(path, cancellationToken);
            DeleteDecryptedTemps(files);
            return new(true, "Paquete firmado y verificado antes de entrega.", fileName, path, packageHash, signature.CertificateSha256);
        }
        catch { if (File.Exists(path)) File.Delete(path); DeleteDecryptedTemps(files); throw; }
    }

    private static void DeleteDecryptedTemps(List<(string ArchivePath, string SourcePath, byte[]? Content, PackageManifestEntry Manifest)> files)
    {
        foreach (var file in files)
            if (file.SourcePath.EndsWith(".plain", StringComparison.Ordinal) && File.Exists(file.SourcePath)) File.Delete(file.SourcePath);
    }

    private static byte[] BuildCanonicalManifest(ForensicCase item, IEnumerable<PackageManifestEntry> entries)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = false }))
        {
            writer.WriteStartObject(); writer.WriteString("schema", "atlas-forense-package/v1"); writer.WriteString("caseId", item.Id); writer.WriteString("folio", item.Folio);
            writer.WriteNumber("reportVersion", item.Report!.Version); writer.WriteString("reportHash", item.Report.IntegrityHash); writer.WriteString("reviewedHash", item.ReportReview!.ReviewedReportHash);
            writer.WriteString("auditHead", item.AuditTrail.LastOrDefault()?.EntryHash ?? "GENESIS"); writer.WriteStartArray("entries");
            foreach (var entry in entries.OrderBy(x => x.Path, StringComparer.Ordinal)) { writer.WriteStartObject(); writer.WriteString("path", entry.Path); writer.WriteNumber("size", entry.SizeBytes); writer.WriteString("sha256", entry.Sha256); writer.WriteString("classification", entry.Classification); writer.WriteEndObject(); }
            writer.WriteEndArray(); writer.WriteEndObject();
        }
        return stream.ToArray();
    }

    private static ZipArchiveEntry CreateEntry(ZipArchive archive, string name) { var entry = archive.CreateEntry(name, CompressionLevel.Optimal); entry.LastWriteTime = DeterministicZipTime; return entry; }
    private static async Task WriteEntryAsync(ZipArchive archive, string name, byte[] content, CancellationToken token) { await using var stream = CreateEntry(archive, name).Open(); await stream.WriteAsync(content, token); }
    private static string SafeName(string value) { var name = Path.GetFileName(value); return string.Concat(name.Select(character => char.IsLetterOrDigit(character) || character is '.' or '-' or '_' ? character : '_')); }
    private static string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    private static async Task<string> HashFileAsync(string path, CancellationToken token) { await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 131072, true); return Convert.ToHexString(await SHA256.HashDataAsync(stream, token)).ToLowerInvariant(); }
    private static bool VerifySignature(byte[] manifest, PackageSignature signature)
    {
        using var certificate = System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPem(PemEncoding.WriteString("CERTIFICATE", signature.PublicCertificate));
        return signature.Algorithm switch
        {
            "RSA-PSS-SHA256" => certificate.GetRSAPublicKey()?.VerifyData(manifest, signature.Signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss) == true,
            "ECDSA-SHA256" => certificate.GetECDsaPublicKey()?.VerifyData(manifest, signature.Signature, HashAlgorithmName.SHA256) == true,
            _ => false
        };
    }
    private static async Task<bool> VerifyWrittenPackageAsync(string path, IEnumerable<PackageManifestEntry> entries, CancellationToken token)
    {
        await using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 131072, true);
        using var archive = new ZipArchive(input, ZipArchiveMode.Read, leaveOpen: true);
        foreach (var expected in entries)
        {
            var entry = archive.GetEntry(expected.Path);
            if (entry is null || entry.Length != expected.SizeBytes) return false;
            await using var content = entry.Open();
            var hash = Convert.ToHexString(await SHA256.HashDataAsync(content, token)).ToLowerInvariant();
            if (!hash.Equals(expected.Sha256, StringComparison.OrdinalIgnoreCase)) return false;
        }
        return true;
    }
}

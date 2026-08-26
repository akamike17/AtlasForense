using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

if (args.Length is < 1 or > 2)
{
    Console.Error.WriteLine("Uso: AtlasForense.Verifier <paquete.afpkg> [certificado-confiable.cer]");
    return 2;
}

try
{
    var result = await VerifyAsync(Path.GetFullPath(args[0]), args.Length == 2 ? Path.GetFullPath(args[1]) : null);
    Console.WriteLine(result.Message);
    return result.Success ? 0 : 1;
}
catch (Exception exception) when (exception is IOException or InvalidDataException or CryptographicException or JsonException or UnauthorizedAccessException)
{
    Console.Error.WriteLine($"PAQUETE NO VÁLIDO: {exception.Message}");
    return 1;
}

static async Task<(bool Success, string Message)> VerifyAsync(string packagePath, string? trustedCertificatePath)
{
    if (!File.Exists(packagePath)) return (false, "PAQUETE NO VÁLIDO: archivo no encontrado.");
    await using var input = new FileStream(packagePath, FileMode.Open, FileAccess.Read, FileShare.Read, 131072, FileOptions.Asynchronous | FileOptions.SequentialScan);
    using var archive = new ZipArchive(input, ZipArchiveMode.Read, leaveOpen: true);
    var names = new HashSet<string>(StringComparer.Ordinal);
    foreach (var entry in archive.Entries)
    {
        if (!names.Add(entry.FullName) || !SafeArchivePath(entry.FullName)) throw new InvalidDataException("Nombre duplicado o ruta insegura en el paquete.");
    }
    var manifest = await ReadRequiredAsync(archive, "manifest.json", 10 * 1024 * 1024);
    var signature = await ReadRequiredAsync(archive, "signature.bin", 1024 * 1024);
    var certificateBytes = await ReadRequiredAsync(archive, "signer.cer", 1024 * 1024);
    var algorithm = System.Text.Encoding.ASCII.GetString(await ReadRequiredAsync(archive, "signature-algorithm.txt", 128));
    using var certificate = X509Certificate2.CreateFromPem(PemEncoding.WriteString("CERTIFICATE", certificateBytes));
    var certificateHash = Convert.ToHexString(SHA256.HashData(certificateBytes)).ToLowerInvariant();
    if (trustedCertificatePath is not null)
    {
        var trustedHash = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(trustedCertificatePath))).ToLowerInvariant();
        if (!CryptographicOperations.FixedTimeEquals(Convert.FromHexString(certificateHash), Convert.FromHexString(trustedHash))) throw new CryptographicException("El certificado del paquete no coincide con el certificado confiable.");
    }
    var signatureValid = algorithm switch
    {
        "RSA-PSS-SHA256" => certificate.GetRSAPublicKey()?.VerifyData(manifest, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss) == true,
        "ECDSA-SHA256" => certificate.GetECDsaPublicKey()?.VerifyData(manifest, signature, HashAlgorithmName.SHA256) == true,
        _ => throw new CryptographicException("Algoritmo de firma no admitido.")
    };
    if (!signatureValid) throw new CryptographicException("La firma del manifiesto no es válida.");

    using var document = JsonDocument.Parse(manifest);
    if (document.RootElement.GetProperty("schema").GetString() != "atlas-forense-package/v1") throw new InvalidDataException("Esquema de manifiesto no compatible.");
    var listed = new HashSet<string>(StringComparer.Ordinal);
    foreach (var item in document.RootElement.GetProperty("entries").EnumerateArray())
    {
        var path = item.GetProperty("path").GetString() ?? throw new InvalidDataException("Entrada sin ruta.");
        if (!listed.Add(path) || !SafeArchivePath(path)) throw new InvalidDataException("Ruta insegura o duplicada en el manifiesto.");
        var entry = archive.GetEntry(path) ?? throw new InvalidDataException($"Falta la entrada {path}.");
        if (entry.Length != item.GetProperty("size").GetInt64()) throw new InvalidDataException($"Tamaño modificado: {path}.");
        await using var content = entry.Open();
        var actual = Convert.ToHexString(await SHA256.HashDataAsync(content)).ToLowerInvariant();
        if (!actual.Equals(item.GetProperty("sha256").GetString(), StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException($"SHA-256 modificado: {path}.");
    }
    if (archive.Entries.Any(entry => (entry.FullName.StartsWith("evidence/", StringComparison.Ordinal) || entry.FullName.StartsWith("report/", StringComparison.Ordinal)) && !listed.Contains(entry.FullName)))
        throw new InvalidDataException("El paquete contiene contenido no declarado.");
    return (true, $"PAQUETE VÁLIDO. Firma: {algorithm}; certificado SHA-256: {certificateHash}; entradas verificadas: {listed.Count}.");
}

static async Task<byte[]> ReadRequiredAsync(ZipArchive archive, string name, long maximum)
{
    var entry = archive.GetEntry(name) ?? throw new InvalidDataException($"Falta {name}.");
    if (entry.Length > maximum) throw new InvalidDataException($"{name} excede el límite.");
    await using var source = entry.Open(); using var output = new MemoryStream((int)entry.Length); await source.CopyToAsync(output); return output.ToArray();
}

static bool SafeArchivePath(string path) => !string.IsNullOrWhiteSpace(path) && !path.StartsWith('/') && !path.StartsWith('\\') && !path.Contains("..", StringComparison.Ordinal) && !path.Contains('\\') && !Path.IsPathRooted(path);

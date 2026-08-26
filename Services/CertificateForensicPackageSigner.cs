using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AtlasForense.Models;

namespace AtlasForense.Services;

public sealed class CertificateForensicPackageSigner(IConfiguration configuration) : IForensicPackageSigner
{
    public bool IsAvailable => FindCertificate(requirePrivateKey: true) is not null;

    public PackageSignature Sign(ReadOnlySpan<byte> canonicalManifest)
    {
        using var certificate = FindCertificate(requirePrivateKey: true) ?? throw new InvalidOperationException("No existe un certificado de firma configurado con clave privada.");
        byte[] signature;
        string algorithm;
        using (var rsa = certificate.GetRSAPrivateKey())
        {
            if (rsa is not null) { signature = rsa.SignData(canonicalManifest, HashAlgorithmName.SHA256, RSASignaturePadding.Pss); algorithm = "RSA-PSS-SHA256"; }
            else
            {
                using var ecdsa = certificate.GetECDsaPrivateKey() ?? throw new InvalidOperationException("El certificado no usa una clave RSA o ECDSA compatible.");
                signature = ecdsa.SignData(canonicalManifest, HashAlgorithmName.SHA256); algorithm = "ECDSA-SHA256";
            }
        }
        var publicCertificate = certificate.Export(X509ContentType.Cert);
        return new(signature, publicCertificate, algorithm, Convert.ToHexString(SHA256.HashData(publicCertificate)).ToLowerInvariant());
    }

    private X509Certificate2? FindCertificate(bool requirePrivateKey)
    {
        var thumbprint = configuration["Signing:CertificateThumbprint"]?.Replace(" ", string.Empty, StringComparison.Ordinal);
        if (string.IsNullOrWhiteSpace(thumbprint)) return null;
        var location = Enum.TryParse<StoreLocation>(configuration["Signing:StoreLocation"], true, out var parsed) ? parsed : StoreLocation.CurrentUser;
        using var store = new X509Store(StoreName.My, location);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        var certificate = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: true).OfType<X509Certificate2>().FirstOrDefault(x => !requirePrivateKey || x.HasPrivateKey);
        return certificate is null ? null : new X509Certificate2(certificate);
    }
}

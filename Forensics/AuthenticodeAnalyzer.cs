using System.Buffers.Binary;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using AtlasForense.Models;

namespace AtlasForense.Forensics;

public sealed class AuthenticodeAnalyzer : IForensicAnalyzer
{
    private const int MaxFileBytes = 256 * 1024 * 1024;
    public string Id => "windows-authenticode";
    public string Version => "1.0.0";
    public bool CanAnalyze(EvidenceItem evidence) => new[] { ".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".efi" }.Contains(Path.GetExtension(evidence.OriginalFileName), StringComparer.OrdinalIgnoreCase);

    public async Task<AnalyzerOutput> AnalyzeAsync(AnalyzerContext context)
    {
        var info = new FileInfo(context.FilePath);
        if (info.Length > MaxFileBytes) throw new InvalidDataException($"El archivo excede el límite Authenticode de {MaxFileBytes} bytes.");
        var data = await File.ReadAllBytesAsync(context.FilePath, context.CancellationToken);
        var layout = ReadSecurityLayout(data);
        var output = new AnalyzerOutput();
        if (layout.CertificateOffset == 0 || layout.CertificateSize == 0)
        {
            Add(output, context, "Estado Authenticode", "Sin firma", "Security Directory ausente.", ConfidenceLevel.Observed);
            output.Summary = "Authenticode: no se observó firma embebida; esto no implica por sí mismo contenido malicioso.";
            return output;
        }
        if (layout.CertificateOffset > data.Length - 8 || layout.CertificateSize > data.Length - layout.CertificateOffset)
            throw new InvalidDataException("La tabla de certificados Authenticode queda fuera del archivo.");
        var certificateLength = checked((int)ReadUInt32(data, layout.CertificateOffset));
        var revision = ReadUInt16(data, layout.CertificateOffset + 4);
        var type = ReadUInt16(data, layout.CertificateOffset + 6);
        if (certificateLength < 8 || certificateLength > layout.CertificateSize || layout.CertificateOffset > data.Length - certificateLength)
            throw new InvalidDataException("WIN_CERTIFICATE declara una longitud inválida.");
        if (revision != 0x0200 || type != 0x0002) throw new InvalidDataException($"WIN_CERTIFICATE no contiene PKCS#7 Authenticode compatible (revisión 0x{revision:X4}, tipo 0x{type:X4}).");

        var cms = new SignedCms();
        try { cms.Decode(data.AsSpan(layout.CertificateOffset + 8, certificateLength - 8).ToArray()); }
        catch (CryptographicException exception) { throw new InvalidDataException("El contenedor PKCS#7 Authenticode no es válido.", exception); }
        var signatureValid = CheckCmsSignature(cms);
        var digest = ReadIndirectDigest(cms.ContentInfo.Content);
        var computed = ComputeAuthenticodeHash(data, layout, digest.Algorithm);
        var digestMatches = CryptographicOperations.FixedTimeEquals(digest.Value, computed);
        var signer = cms.SignerInfos.Count > 0 ? cms.SignerInfos[0].Certificate : null;
        var chainStatus = "El PKCS#7 no contiene un certificado firmante.";
        var chainTrusted = signer is not null && BuildOfflineChain(signer, cms.Certificates, out chainStatus);

        Add(output, context, "Estado Authenticode", signatureValid && digestMatches ? "Firma criptográficamente válida" : "Firma inválida", $"firmaPKCS7={signatureValid}; digestCoincide={digestMatches}; confianzaLocal={chainTrusted}", signatureValid && digestMatches ? ConfidenceLevel.Confirmed : ConfidenceLevel.Observed);
        Add(output, context, "Digest Authenticode", Convert.ToHexString(computed).ToLowerInvariant(), $"algoritmo={digest.Algorithm.Name}; esperado={Convert.ToHexString(digest.Value).ToLowerInvariant()}", digestMatches ? ConfidenceLevel.Confirmed : ConfidenceLevel.Observed);
        Add(output, context, "Confianza local offline", chainTrusted ? "Confiable" : "No establecida", chainStatus, ConfidenceLevel.Observed);
        if (signer is not null)
        {
            Add(output, context, "Firmante", signer.Subject, $"emisor={signer.Issuer}; serie={signer.SerialNumber}", ConfidenceLevel.Observed);
            Add(output, context, "Huella del certificado", signer.Thumbprint, $"válidoDesde={signer.NotBefore:O}; válidoHasta={signer.NotAfter:O}", ConfidenceLevel.Observed);
            output.Entities.Add(new CaseEntity { Type = "Certificate", Value = signer.Thumbprint.ToLowerInvariant(), DisplayName = signer.GetNameInfo(X509NameType.SimpleName, false), Confidence = ConfidenceLevel.Observed, EvidenceIds = [context.Evidence.Id] });
        }
        output.Summary = $"Authenticode: PKCS#7 {(signatureValid ? "válido" : "inválido")}; digest {(digestMatches ? "coincidente" : "diferente")}; confianza local offline {(chainTrusted ? "establecida" : "no establecida")}.";
        return output;
    }

    private static SecurityLayout ReadSecurityLayout(byte[] data)
    {
        if (data.Length < 64 || data[0] != 'M' || data[1] != 'Z') throw new InvalidDataException("Firma DOS MZ ausente.");
        var pe = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(0x3c, 4));
        if (pe < 64 || pe > data.Length - 24 || !data.AsSpan(pe, 4).SequenceEqual("PE\0\0"u8)) throw new InvalidDataException("Cabecera PE inválida.");
        var optional = pe + 24;
        var optionalSize = ReadUInt16(data, pe + 20);
        if (optional > data.Length - optionalSize || optionalSize < 72) throw new InvalidDataException("Cabecera opcional PE truncada.");
        var magic = ReadUInt16(data, optional);
        var directory = magic switch { 0x10b => optional + 96 + 32, 0x20b => optional + 112 + 32, _ => throw new InvalidDataException("Formato PE opcional desconocido.") };
        if (directory > optional + optionalSize - 8) return new SecurityLayout(optional + 64, directory, 0, 0);
        var certificateOffset = checked((int)ReadUInt32(data, directory));
        var certificateSize = checked((int)ReadUInt32(data, directory + 4));
        return new SecurityLayout(optional + 64, directory, certificateOffset, certificateSize);
    }

    private static bool CheckCmsSignature(SignedCms cms)
    {
        try { cms.CheckSignature(verifySignatureOnly: true); return cms.SignerInfos.Count > 0; }
        catch (CryptographicException) { return false; }
    }

    private static DigestValue ReadIndirectDigest(byte[] content)
    {
        try
        {
            var reader = new AsnReader(content, AsnEncodingRules.DER);
            var outer = reader.ReadSequence();
            var data = outer.ReadSequence();
            _ = data.ReadObjectIdentifier();
            while (data.HasData) _ = data.ReadEncodedValue();
            var digestInfo = outer.ReadSequence();
            var algorithmInfo = digestInfo.ReadSequence();
            var oid = algorithmInfo.ReadObjectIdentifier();
            while (algorithmInfo.HasData) _ = algorithmInfo.ReadEncodedValue();
            var value = digestInfo.ReadOctetString();
            digestInfo.ThrowIfNotEmpty(); outer.ThrowIfNotEmpty(); reader.ThrowIfNotEmpty();
            var algorithm = oid switch { "1.3.14.3.2.26" => HashAlgorithmName.SHA1, "2.16.840.1.101.3.4.2.1" => HashAlgorithmName.SHA256, "2.16.840.1.101.3.4.2.2" => HashAlgorithmName.SHA384, "2.16.840.1.101.3.4.2.3" => HashAlgorithmName.SHA512, _ => throw new InvalidDataException($"Algoritmo de digest Authenticode no soportado: {oid}.") };
            if (value.Length != HashLength(algorithm)) throw new InvalidDataException("El digest Authenticode tiene longitud inválida.");
            return new DigestValue(algorithm, value);
        }
        catch (AsnContentException exception) { throw new InvalidDataException("SpcIndirectDataContent no es ASN.1 DER válido.", exception); }
    }

    private static byte[] ComputeAuthenticodeHash(byte[] data, SecurityLayout layout, HashAlgorithmName algorithm)
    {
        using var hash = IncrementalHash.CreateHash(algorithm);
        Append(hash, data, 0, layout.ChecksumOffset);
        Append(hash, data, layout.ChecksumOffset + 4, layout.SecurityDirectoryOffset - (layout.ChecksumOffset + 4));
        Append(hash, data, layout.SecurityDirectoryOffset + 8, layout.CertificateOffset - (layout.SecurityDirectoryOffset + 8));
        var afterCertificate = checked(layout.CertificateOffset + layout.CertificateSize);
        Append(hash, data, afterCertificate, data.Length - afterCertificate);
        return hash.GetHashAndReset();
    }

    private static void Append(IncrementalHash hash, byte[] data, int offset, int length)
    {
        if (offset < 0 || length < 0 || offset > data.Length - length) throw new InvalidDataException("Los segmentos Authenticode se traslapan o quedan fuera del archivo.");
        if (length > 0) hash.AppendData(data, offset, length);
    }

    private static bool BuildOfflineChain(X509Certificate2 signer, X509Certificate2Collection certificates, out string status)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.ExtraStore.AddRange(certificates);
        var trusted = chain.Build(signer);
        status = chain.ChainStatus.Length == 0 ? "Cadena aceptada por almacenes locales; revocación no consultada." : string.Join("; ", chain.ChainStatus.Select(x => $"{x.Status}: {x.StatusInformation.Trim()}"));
        return trusted;
    }

    private static int HashLength(HashAlgorithmName name) => name == HashAlgorithmName.SHA1 ? 20 : name == HashAlgorithmName.SHA256 ? 32 : name == HashAlgorithmName.SHA384 ? 48 : name == HashAlgorithmName.SHA512 ? 64 : 0;
    private static ushort ReadUInt16(byte[] data, int offset) => BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(offset, 2));
    private static uint ReadUInt32(byte[] data, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset, 4));
    private static void Add(AnalyzerOutput output, AnalyzerContext context, string name, string value, string detail, ConfidenceLevel confidence) => output.Artifacts.Add(new AnalysisArtifact { EvidenceId = context.Evidence.Id, AnalysisRunId = context.AnalysisRunId, Kind = ArtifactKind.Metadata, Name = name, Value = value, Context = detail, Confidence = confidence });
    private sealed record DigestValue(HashAlgorithmName Algorithm, byte[] Value);
    private readonly record struct SecurityLayout(int ChecksumOffset, int SecurityDirectoryOffset, int CertificateOffset, int CertificateSize);
}

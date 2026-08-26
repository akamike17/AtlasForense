using System.Buffers.Binary;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using AtlasForense.Forensics;
using AtlasForense.Models;
using Xunit;

namespace AtlasForense.Tests;

public sealed class AuthenticodeAnalyzerTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"atlas-authenticode-{Guid.NewGuid():N}.exe");

    [Fact]
    public async Task Analyzer_DistinguishesValidSignatureDigestAndOfflineTrust()
    {
        await File.WriteAllBytesAsync(_path, BuildSignedPe());
        var evidence = new EvidenceItem { Id = Guid.NewGuid(), OriginalFileName = "signed.exe" };

        var output = await new AuthenticodeAnalyzer().AnalyzeAsync(new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), evidence, _path, default));

        Assert.Contains(output.Artifacts, x => x.Name == "Estado Authenticode" && x.Value == "Firma criptográficamente válida" && x.Confidence == ConfidenceLevel.Confirmed);
        Assert.Contains(output.Artifacts, x => x.Name == "Digest Authenticode" && x.Context.Contains("algoritmo=SHA256"));
        Assert.Contains(output.Artifacts, x => x.Name == "Firmante" && x.Value.Contains("AtlasForense Test Signer"));
        Assert.Contains(output.Artifacts, x => x.Name == "Confianza local offline" && x.Value == "No establecida");
        Assert.Single(output.Entities, x => x.Type == "Certificate");
    }

    [Fact]
    public async Task Analyzer_DetectsPostSignatureTamperingEvenWhenCmsSignatureRemainsValid()
    {
        var data = BuildSignedPe();
        data[10] ^= 0x5a;
        await File.WriteAllBytesAsync(_path, data);
        var evidence = new EvidenceItem { OriginalFileName = "tampered.exe" };

        var output = await new AuthenticodeAnalyzer().AnalyzeAsync(new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), evidence, _path, default));

        Assert.Contains(output.Artifacts, x => x.Name == "Estado Authenticode" && x.Value == "Firma inválida" && x.Context.Contains("firmaPKCS7=True") && x.Context.Contains("digestCoincide=False"));
    }

    [Fact]
    public async Task Analyzer_ReportsUnsignedPeWithoutClaimingMalice()
    {
        await File.WriteAllBytesAsync(_path, BuildUnsignedPe());
        var evidence = new EvidenceItem { OriginalFileName = "unsigned.exe" };

        var output = await new AuthenticodeAnalyzer().AnalyzeAsync(new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), evidence, _path, default));

        Assert.Contains(output.Artifacts, x => x.Name == "Estado Authenticode" && x.Value == "Sin firma");
        Assert.Contains("no implica", output.Summary);
    }

    private static byte[] BuildSignedPe()
    {
        const int certificateOffset = 0x400;
        var unsigned = BuildUnsignedPe(certificateOffset);
        const int optional = 0x98;
        const int securityDirectory = optional + 144;
        BinaryPrimitives.WriteUInt32LittleEndian(unsigned.AsSpan(securityDirectory), certificateOffset);
        var digest = ComputeHash(unsigned, optional + 64, securityDirectory, certificateOffset);
        var indirectData = EncodeIndirectData(digest);
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=AtlasForense Test Signer", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        var cms = new SignedCms(new ContentInfo(new Oid("1.3.6.1.4.1.311.2.1.4"), indirectData), detached: false);
        cms.ComputeSignature(new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, certificate) { IncludeOption = X509IncludeOption.EndCertOnly }, silent: true);
        var encoded = cms.Encode();
        var winLength = 8 + encoded.Length;
        var certificateSize = (winLength + 7) & ~7;
        Array.Resize(ref unsigned, certificateOffset + certificateSize);
        BinaryPrimitives.WriteUInt32LittleEndian(unsigned.AsSpan(securityDirectory + 4), (uint)certificateSize);
        BinaryPrimitives.WriteUInt32LittleEndian(unsigned.AsSpan(certificateOffset), (uint)winLength);
        BinaryPrimitives.WriteUInt16LittleEndian(unsigned.AsSpan(certificateOffset + 4), 0x0200);
        BinaryPrimitives.WriteUInt16LittleEndian(unsigned.AsSpan(certificateOffset + 6), 0x0002);
        encoded.CopyTo(unsigned, certificateOffset + 8);
        return unsigned;
    }

    private static byte[] BuildUnsignedPe(int length = 0x400)
    {
        var data = new byte[length];
        data[0] = (byte)'M'; data[1] = (byte)'Z';
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(0x3c), 0x80);
        "PE\0\0"u8.CopyTo(data.AsSpan(0x80));
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x84), 0x8664);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x94), 0xf0);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x98), 0x20b);
        new Random(77).NextBytes(data.AsSpan(0x200));
        return data;
    }

    private static byte[] ComputeHash(byte[] data, int checksum, int securityDirectory, int certificateOffset)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(data, 0, checksum);
        hash.AppendData(data, checksum + 4, securityDirectory - checksum - 4);
        hash.AppendData(data, securityDirectory + 8, certificateOffset - securityDirectory - 8);
        return hash.GetHashAndReset();
    }

    private static byte[] EncodeIndirectData(byte[] digest)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        writer.PushSequence(); writer.WriteObjectIdentifier("1.3.6.1.4.1.311.2.1.15"); writer.PopSequence();
        writer.PushSequence();
        writer.PushSequence(); writer.WriteObjectIdentifier("2.16.840.1.101.3.4.2.1"); writer.WriteNull(); writer.PopSequence();
        writer.WriteOctetString(digest);
        writer.PopSequence();
        writer.PopSequence();
        return writer.Encode();
    }

    public void Dispose() { if (File.Exists(_path)) File.Delete(_path); }
}

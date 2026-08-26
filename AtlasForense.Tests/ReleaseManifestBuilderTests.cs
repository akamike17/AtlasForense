using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using AtlasForense.Services;
using Xunit;

namespace AtlasForense.Tests;

public sealed class ReleaseManifestBuilderTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"atlas-release-{Guid.NewGuid():N}");

    public ReleaseManifestBuilderTests()
    {
        Directory.CreateDirectory(Path.Combine(_root, "publish", "sub"));
        File.WriteAllText(Path.Combine(_root, "publish", "AtlasForense.dll"), "binario simulado");
        File.WriteAllText(Path.Combine(_root, "publish", "sub", "appsettings.json"), "{}");
    }

    [Fact]
    public async Task Manifest_IsDeterministicallyOrderedAndHashVerified()
    {
        var builder = new ReleaseManifestBuilder();

        var manifest = await builder.BuildAsync(Path.Combine(_root, "publish"), default);

        Assert.Equal(2, manifest.Entries.Count);
        Assert.Equal("AtlasForense.dll", manifest.Entries[0].Path);
        Assert.Equal("sub/appsettings.json", manifest.Entries[1].Path);
        foreach (var entry in manifest.Entries)
        {
            var bytes = await File.ReadAllBytesAsync(Path.Combine(_root, "publish", entry.Path.Replace('/', Path.DirectorySeparatorChar)));
            Assert.Equal(bytes.Length, entry.SizeBytes);
            Assert.Equal(Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(), entry.Sha256);
        }

        var canonical = ReleaseManifestBuilder.CanonicalJson(manifest.Schema, manifest.CreatedAtUtc, manifest.Entries);
        Assert.Equal(manifest.ManifestSha256, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant());
    }

    [Fact]
    public async Task Manifest_CanBeSignedWithCmsAndIndependentlyVerified()
    {
        using var rsa = RSA.Create(3072);
        using var certificate = new CertificateRequest("CN=AtlasForense Release Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var builder = new ReleaseManifestBuilder();
        var manifest = await builder.BuildAsync(Path.Combine(_root, "publish"), default);
        var canonical = Encoding.UTF8.GetBytes(ReleaseManifestBuilder.CanonicalJson(manifest.Schema, manifest.CreatedAtUtc, manifest.Entries));

        var cms = new SignedCms(new ContentInfo(canonical), detached: true);
        cms.ComputeSignature(new CmsSigner(certificate) { IncludeOption = X509IncludeOption.EndCertOnly });
        var signature = cms.Encode();

        var verifier = new SignedCms(new ContentInfo(canonical), detached: true);
        verifier.Decode(signature);
        verifier.CheckSignature(verifySignatureOnly: true);
        Assert.Equal(manifest.ManifestSha256, Convert.ToHexString(SHA256.HashData(canonical)).ToLowerInvariant());
    }

    [Fact]
    public async Task Manifest_RejectsMissingDirectory() =>
        await Assert.ThrowsAsync<DirectoryNotFoundException>(() => new ReleaseManifestBuilder().BuildAsync(Path.Combine(_root, "no-existe"), default));

    public void Dispose() { if (Directory.Exists(_root)) Directory.Delete(_root, true); }
}

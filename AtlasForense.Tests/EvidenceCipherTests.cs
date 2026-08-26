using System.Text;
using AtlasForense.Services;
using Xunit;

namespace AtlasForense.Tests;

public sealed class EvidenceCipherTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"atlas-cipher-{Guid.NewGuid():N}");

    public EvidenceCipherTests() => Directory.CreateDirectory(_root);

    [Fact]
    public async Task RoundTrip_PreservesExactBytesAndDetectsTampering()
    {
        using var cipher = AesGcmEvidenceCipher.Ephemeral();
        var plain = Encoding.UTF8.GetBytes("evidencia conocida para cifrado");
        var plainPath = Path.Combine(_root, "plain.bin");
        var encPath = Path.Combine(_root, "enc.bin");
        await File.WriteAllBytesAsync(plainPath, plain);

        await cipher.EncryptAsync(plainPath, encPath, default);

        Assert.True(cipher.IsEnvelope(encPath));
        Assert.False(cipher.IsEnvelope(plainPath));
        Assert.NotEqual(plain, await File.ReadAllBytesAsync(encPath));
        Assert.Equal(Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(plain)).ToLowerInvariant(), await cipher.ComputePlaintextSha256Async(encPath, default));
        var outPath = Path.Combine(_root, "out.bin");
        await cipher.DecryptAsync(encPath, outPath, default);
        Assert.Equal(plain, await File.ReadAllBytesAsync(outPath));

        await File.AppendAllTextAsync(encPath, "tamper");
        await Assert.ThrowsAsync<InvalidDataException>(() => cipher.ComputePlaintextSha256Async(encPath, default));
    }

    [Fact]
    public async Task RoundTrip_WorksWithEmptyAndLargeMultiChunkFiles()
    {
        using var cipher = AesGcmEvidenceCipher.Ephemeral();
        foreach (var size in new[] { 0, 1, 65536, 17 * 1024 * 1024 })
        {
            var plain = new byte[size];
            new Random(size).NextBytes(plain);
            var plainPath = Path.Combine(_root, $"p{size}.bin");
            var encPath = Path.Combine(_root, $"e{size}.bin");
            var outPath = Path.Combine(_root, $"o{size}.bin");
            await File.WriteAllBytesAsync(plainPath, plain);
            await cipher.EncryptAsync(plainPath, encPath, default);
            await cipher.DecryptAsync(encPath, outPath, default);
            Assert.Equal(plain, await File.ReadAllBytesAsync(outPath));
        }
    }

    public void Dispose() { if (Directory.Exists(_root)) Directory.Delete(_root, true); }
}

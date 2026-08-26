using System.Buffers.Binary;
using System.Security.Cryptography;

namespace AtlasForense.Services;

public interface IEvidenceCipher
{
    Task EncryptAsync(string plaintextPath, string destinationPath, CancellationToken token);
    Task DecryptAsync(string encryptedPath, string destinationPath, CancellationToken token);
    Task<string> ComputePlaintextSha256Async(string encryptedPath, CancellationToken token);
    bool IsEnvelope(string path);
}

// Sobre en reposo: [ATLEV1\0\0][{int32 cipherLen}{12 nonce}{16 tag}{cipher}...]
// Cada trozo se cifra con AES-256-GCM y un nonce aleatorio propio; cualquier
// alteración produce InvalidDataException al descifrar.
public sealed class AesGcmEvidenceCipher : IEvidenceCipher, IDisposable
{
    private const int ChunkSize = 16 * 1024 * 1024;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private static readonly byte[] Magic = "ATLEV1\0\0"u8.ToArray();
    private readonly byte[] _key = new byte[32];

    private AesGcmEvidenceCipher() { }

    public static AesGcmEvidenceCipher Ephemeral()
    {
        var cipher = new AesGcmEvidenceCipher();
        RandomNumberGenerator.Fill(cipher._key);
        return cipher;
    }

    public static AesGcmEvidenceCipher FromProtectedKey(Func<byte[], byte[]> protect, Func<byte[], byte[]> unprotect, string keyPath)
    {
        if (File.Exists(keyPath))
        {
            var raw = unprotect(File.ReadAllBytes(keyPath));
            if (raw.Length != 32) throw new CryptographicException("La clave maestra de evidencia no tiene 32 bytes.");
            var cipher = new AesGcmEvidenceCipher();
            raw.CopyTo(cipher._key, 0);
            CryptographicOperations.ZeroMemory(raw);
            return cipher;
        }
        var created = Ephemeral();
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(keyPath))!);
        File.WriteAllBytes(keyPath, protect((byte[])created._key.Clone()));
        return created;
    }

    public bool IsEnvelope(string path)
    {
        if (!File.Exists(path)) return false;
        var header = new byte[8];
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096);
        if (stream.Length < 8 || stream.Read(header, 0, 8) != 8) return false;
        return header.AsSpan().SequenceEqual(Magic);
    }

    public async Task EncryptAsync(string plaintextPath, string destinationPath, CancellationToken token)
    {
        var tempPath = destinationPath + $".tmp-{Guid.NewGuid():N}";
        try
        {
            await using (var source = new FileStream(plaintextPath, FileMode.Open, FileAccess.Read, FileShare.Read, 131072, true))
            await using (var output = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 131072, true))
            {
                await output.WriteAsync(Magic, token);
                using var aes = new AesGcm(_key, TagSize);
                var plain = new byte[ChunkSize];
                var cipher = new byte[ChunkSize];
                var nonce = new byte[NonceSize];
                var tag = new byte[TagSize];
                var lengthBuffer = new byte[4];
                while (true)
                {
                    token.ThrowIfCancellationRequested();
                    var read = await ReadFullAsync(source, plain, token);
                    RandomNumberGenerator.Fill(nonce);
                    aes.Encrypt(nonce, plain.AsSpan(0, read), cipher.AsSpan(0, read), tag);
                    BinaryPrimitives.WriteInt32LittleEndian(lengthBuffer, read);
                    await output.WriteAsync(lengthBuffer, token);
                    await output.WriteAsync(nonce, token);
                    await output.WriteAsync(tag, token);
                    await output.WriteAsync(cipher.AsMemory(0, read), token);
                    if (read < ChunkSize) break;
                }
                await output.FlushAsync(token);
            }
            File.Move(tempPath, destinationPath);
        }
        catch
        {
            if (File.Exists(tempPath)) File.Delete(tempPath);
            throw;
        }
    }

    public async Task DecryptAsync(string encryptedPath, string destinationPath, CancellationToken token)
    {
        await using var source = OpenEnvelope(encryptedPath);
        await using var output = new FileStream(destinationPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 131072, true);
        await ForEachPlaintextChunkAsync(source, async (memory, ct) => await output.WriteAsync(memory, ct), token);
        await output.FlushAsync(token);
    }

    public async Task<string> ComputePlaintextSha256Async(string encryptedPath, CancellationToken token)
    {
        await using var source = OpenEnvelope(encryptedPath);
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        await ForEachPlaintextChunkAsync(source, (memory, _) => { sha.AppendData(memory.Span); return Task.CompletedTask; }, token);
        return Convert.ToHexString(sha.GetHashAndReset()).ToLowerInvariant();
    }

    private async Task ForEachPlaintextChunkAsync(Stream source, Func<Memory<byte>, CancellationToken, Task> sink, CancellationToken token)
    {
        using var aes = new AesGcm(_key, TagSize);
        var lengthBuffer = new byte[4];
        var nonce = new byte[NonceSize];
        var tag = new byte[TagSize];
        var cipher = new byte[ChunkSize];
        var plain = new byte[ChunkSize];
        while (true)
        {
            token.ThrowIfCancellationRequested();
            var readLength = await ReadFullAsync(source, lengthBuffer, token);
            if (readLength == 0) break;
            if (readLength < 4) throw new InvalidDataException("El sobre de evidencia está truncado en la longitud de trozo.");
            var chunkLength = BinaryPrimitives.ReadInt32LittleEndian(lengthBuffer);
            if (chunkLength < 0 || chunkLength > ChunkSize) throw new InvalidDataException("El sobre de evidencia declara un trozo de tamaño imposible.");
            if (await ReadFullAsync(source, nonce, token) != NonceSize || await ReadFullAsync(source, tag, token) != TagSize)
                throw new InvalidDataException("El sobre de evidencia está truncado en nonce o etiqueta.");
            if (chunkLength > 0 && await ReadFullAsync(source, cipher.AsMemory(0, chunkLength), token) != chunkLength)
                throw new InvalidDataException("El sobre de evidencia está truncado en el cifrado.");
            try { aes.Decrypt(nonce, cipher.AsSpan(0, chunkLength), tag, plain.AsSpan(0, chunkLength)); }
            catch (CryptographicException exception) { throw new InvalidDataException("La evidencia cifrada no pudo descifrarse; fue alterada o la clave no corresponde.", exception); }
            await sink(plain.AsMemory(0, chunkLength), token);
        }
    }

    private static FileStream OpenEnvelope(string encryptedPath)
    {
        var stream = new FileStream(encryptedPath, FileMode.Open, FileAccess.Read, FileShare.Read, 131072, true);
        var header = new byte[8];
        if (stream.Length < 8 || stream.Read(header, 0, 8) != 8 || !header.AsSpan().SequenceEqual(Magic))
        {
            stream.Dispose();
            throw new InvalidDataException("El archivo no es un sobre de evidencia cifrada ATLEV1.");
        }
        return stream;
    }

    private static async Task<int> ReadFullAsync(Stream stream, Memory<byte> buffer, CancellationToken token)
    {
        var total = 0;
        while (total < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer[total..], token);
            if (read == 0) break;
            total += read;
        }
        return total;
    }

    public void Dispose() => CryptographicOperations.ZeroMemory(_key);
}

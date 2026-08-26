using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AtlasForense.Services;

public sealed record ReleaseManifestEntry(string Path, long SizeBytes, string Sha256);
public sealed record ReleaseManifest(string Schema, DateTimeOffset CreatedAtUtc, IReadOnlyList<ReleaseManifestEntry> Entries, string ManifestSha256);

public interface IReleaseManifestBuilder
{
    Task<ReleaseManifest> BuildAsync(string publishDirectory, CancellationToken token);
}

// Manifiesto de release firmable: inventario determinista (rutas ordenadas,
// SHA-256 por archivo) de la publicación. El manifiesto se firma con el mismo
// mecanismo CMS que los paquetes forenses y puede verificarse de forma
// independiente con AtlasForense.Verifier.
public sealed class ReleaseManifestBuilder : IReleaseManifestBuilder
{
    public async Task<ReleaseManifest> BuildAsync(string publishDirectory, CancellationToken token)
    {
        if (!Directory.Exists(publishDirectory)) throw new DirectoryNotFoundException("El directorio de publicación no existe.");
        var root = Path.GetFullPath(publishDirectory);
        var entries = new List<ReleaseManifestEntry>();
        foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories).OrderBy(x => Path.GetRelativePath(root, x), StringComparer.Ordinal))
        {
            token.ThrowIfCancellationRequested();
            await using var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read, 131072, true);
            var hash = Convert.ToHexString(await SHA256.HashDataAsync(stream, token)).ToLowerInvariant();
            entries.Add(new ReleaseManifestEntry(Path.GetRelativePath(root, file).Replace('\\', '/'), stream.Length, hash));
        }
        var createdAt = DateTimeOffset.UtcNow;
        var canonical = CanonicalJson("atlas-forense-release/v1", createdAt, entries);
        return new ReleaseManifest("atlas-forense-release/v1", createdAt, entries, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant());
    }

    public static string CanonicalJson(string schema, DateTimeOffset createdAt, IReadOnlyList<ReleaseManifestEntry> entries)
    {
        using var stream = new MemoryStream();
        using (var writer = new System.Text.Json.Utf8JsonWriter(stream, new JsonWriterOptions { Indented = false }))
        {
            writer.WriteStartObject();
            writer.WriteString("schema", schema);
            writer.WriteString("createdAtUtc", createdAt.ToUniversalTime().ToString("O"));
            writer.WriteStartArray("entries");
            foreach (var entry in entries.OrderBy(x => x.Path, StringComparer.Ordinal))
            {
                writer.WriteStartObject();
                writer.WriteString("path", entry.Path);
                writer.WriteNumber("sizeBytes", entry.SizeBytes);
                writer.WriteString("sha256", entry.Sha256);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WriteEndObject();
        }
        return Encoding.UTF8.GetString(stream.ToArray());
    }
}

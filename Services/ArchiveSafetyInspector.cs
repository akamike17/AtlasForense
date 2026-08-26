using System.IO.Compression;
using AtlasForense.Models;
using Microsoft.Extensions.Options;

namespace AtlasForense.Services;

public sealed class ArchiveSafetyInspector(IOptions<ForensicStorageOptions> options) : IArchiveSafetyInspector
{
    private readonly ForensicStorageOptions _options = options.Value;

    public Task<ArchiveSafetyResult> InspectZipAsync(string path, CancellationToken cancellationToken)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.SequentialScan);
            using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: false);
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            long expanded = 0;
            var count = 0;
            foreach (var entry in archive.Entries)
            {
                cancellationToken.ThrowIfCancellationRequested();
                count++;
                if (count > _options.MaxArchiveEntries) return Task.FromResult(new ArchiveSafetyResult(false, "El archivo excede el máximo de entradas.", count, expanded));
                if (!SafePath(entry.FullName)) return Task.FromResult(new ArchiveSafetyResult(false, "El archivo contiene una ruta insegura.", count, expanded));
                if (!names.Add(entry.FullName)) return Task.FromResult(new ArchiveSafetyResult(false, "El archivo contiene nombres duplicados.", count, expanded));
                if (IsSymbolicLink(entry)) return Task.FromResult(new ArchiveSafetyResult(false, "El archivo contiene un enlace simbólico.", count, expanded));
                if (entry.FullName.Count(character => character == '/') > _options.MaxArchiveDepth) return Task.FromResult(new ArchiveSafetyResult(false, "El archivo excede la profundidad permitida.", count, expanded));
                try { expanded = checked(expanded + entry.Length); } catch (OverflowException) { return Task.FromResult(new ArchiveSafetyResult(false, "El tamaño expandido se desbordó.", count, long.MaxValue)); }
                if (expanded > _options.MaxArchiveExpandedBytes) return Task.FromResult(new ArchiveSafetyResult(false, "El tamaño expandido excede el límite.", count, expanded));
                if (entry.Length > 0 && (double)entry.Length / Math.Max(1, entry.CompressedLength) > _options.MaxCompressionRatio)
                    return Task.FromResult(new ArchiveSafetyResult(false, "La relación de compresión indica una posible bomba.", count, expanded));
            }
            return Task.FromResult(new ArchiveSafetyResult(true, "Inventario ZIP seguro.", count, expanded));
        }
        catch (InvalidDataException) { return Task.FromResult(new ArchiveSafetyResult(false, "El archivo ZIP está corrupto o truncado.", 0, 0)); }
    }

    private static bool SafePath(string path) => !string.IsNullOrWhiteSpace(path) && !path.StartsWith('/') && !path.StartsWith('\\') && !path.Contains('\\') && !Path.IsPathRooted(path) && path.Split('/').All(part => part is not ".." and not ".");
    private static bool IsSymbolicLink(ZipArchiveEntry entry) => ((entry.ExternalAttributes >> 16) & 0xF000) == 0xA000;
}

using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using AtlasForense.Models;

namespace AtlasForense.Forensics;

public sealed class PrefetchAnalyzer : IForensicAnalyzer
{
    private const int MaxInspectionBytes = 8 * 1024 * 1024;
    private const int MaxStrings = 300;
    public string Id => "windows-prefetch";
    public string Version => "1.0.0";

    public bool CanAnalyze(EvidenceItem evidence) =>
        Path.GetExtension(evidence.OriginalFileName).Equals(".pf", StringComparison.OrdinalIgnoreCase) ||
        evidence.DetectedFileType.Equals("PREFETCH", StringComparison.OrdinalIgnoreCase);

    public async Task<AnalyzerOutput> AnalyzeAsync(AnalyzerContext context)
    {
        var data = await ReadBounded(context.FilePath, context.CancellationToken);
        var output = new AnalyzerOutput();
        if (data.Length < 0x80) throw new InvalidDataException("El archivo Prefetch está truncado antes de completar su cabecera.");
        if (data.Length >= 3 && data[0] == (byte)'M' && data[1] == (byte)'A' && data[2] == (byte)'M')
            throw new InvalidDataException("El Prefetch está dentro de un contenedor comprimido MAM (Windows 11 24H2+); se requiere descompresión previa fuera de esta fase estática.");
        var version = ReadUInt32(data, 0);
        var magic = ReadUInt32(data, 4);
        if (magic != 0x41434353) throw new InvalidDataException("La evidencia no contiene la firma SCCA de un archivo Prefetch.");
        if (version is not (17 or 23 or 26 or 30)) throw new InvalidDataException($"La versión Prefetch {version} no está soportada (se esperan 17, 23, 26 o 30).");

        var declaredSize = ReadUInt32(data, 4 + 4);
        var name = ReadUtf16Fixed(data, 12, 60);
        var hash = ReadUInt32(data, 0x48);
        var flags = ReadUInt32(data, 0x4c);
        Add(output, context, ArtifactKind.Metadata, "Ejecutable Prefetch", string.IsNullOrWhiteSpace(name) ? "<sin nombre>" : name, $"versión={version}; hash=0x{hash:X8}; flags=0x{flags:X}");
        if (!output.Entities.Any(x => x.Type == "File" && x.Value.Equals(name, StringComparison.OrdinalIgnoreCase)))
            output.Entities.Add(new CaseEntity { Type = "File", Value = name.ToLowerInvariant(), DisplayName = name, Confidence = ConfidenceLevel.Observed, EvidenceIds = [context.Evidence.Id] });

        if (declaredSize != data.Length)
            Add(output, context, ArtifactKind.Capability, "Tamaño Prefetch inconsistente", $"declarado={declaredSize}; observado={data.Length}", "El tamaño declarado en la cabecera no coincide con el archivo preservado; puede indicar truncamiento o edición.", ConfidenceLevel.Inferred);

        var stringsOffset = ReadUInt32(data, 0x64);
        var stringsSize = ReadUInt32(data, 0x68);
        var referenced = 0;
        if (stringsOffset >= 0x80 && stringsSize >= 4 && (long)stringsOffset + stringsSize <= data.Length && stringsSize <= MaxInspectionBytes)
        {
            foreach (var value in ReadUtf16Strings(data, (int)stringsOffset, (int)stringsSize).Take(MaxStrings))
            {
                referenced++;
                Add(output, context, ArtifactKind.Metadata, "Archivo referenciado", value, "Cadena UTF-16 de la sección de nombres del Prefetch; módulo o archivo tocado durante la ejecución declarada.");
            }
        }
        else Add(output, context, ArtifactKind.Capability, "Sección de cadenas inválida", $"offset={stringsOffset}; tamaño={stringsSize}", "La sección declarada de nombres queda fuera del límite de inspección.", ConfidenceLevel.Inferred);

        if (version >= 23 && data.Length >= 0xc0)
        {
            var runCount = ReadUInt32(data, 0x7c);
            Add(output, context, ArtifactKind.Metadata, "Conteo de ejecuciones", runCount.ToString(CultureInfo.InvariantCulture), "Declarado en la cabecera Prefetch v23+; no es una prueba absoluta de ejecución.");
            var recorded = 0;
            for (var index = 0; index < 8; index++)
            {
                var ticks = (long)ReadUInt64(data, 0x80 + index * 8);
                if (ticks <= 0 || !TryFileTime(ticks, out var when)) continue;
                recorded++;
                Add(output, context, ArtifactKind.Metadata, "Última ejecución declarada", when.ToString("O"), $"entrada={index}; FILETIME={ticks}");
                output.Events.Add(new TimelineEvent { EvidenceId = context.Evidence.Id, OccurredAtUtc = when, Category = "Prefetch", Title = $"Ejecución declarada de {name}", Description = $"Entrada de última ejecución {index} declarada en la cabecera Prefetch.", Source = $"{context.Evidence.Identifier}/prefetch-header", Confidence = ConfidenceLevel.Inferred });
            }
            if (runCount > 0 && recorded == 0)
                Add(output, context, ArtifactKind.Capability, "Conteo sin marcas de tiempo", runCount.ToString(CultureInfo.InvariantCulture), "El contador de ejecuciones es positivo pero ninguna marca de tiempo es plausible.", ConfidenceLevel.Inferred);
        }

        output.Summary = $"Prefetch v{version}: {(string.IsNullOrWhiteSpace(name) ? "<sin nombre>" : name)}, hash 0x{hash:X8}, {referenced} referencia(s); muestra no ejecutada.";
        return output;
    }

    private static string ReadUtf16Fixed(byte[] data, int offset, int length)
    {
        var end = length;
        for (var index = 0; index + 1 < length; index += 2)
            if (data[offset + index] == 0 && data[offset + index + 1] == 0) { end = index; break; }
        return end == 0 ? string.Empty : Encoding.Unicode.GetString(data, offset, end).TrimEnd('\0');
    }

    private static IEnumerable<string> ReadUtf16Strings(byte[] data, int offset, int length)
    {
        var builder = new StringBuilder();
        for (var index = 0; index + 1 < length; index += 2)
        {
            var character = (char)(data[offset + index] | (data[offset + index + 1] << 8));
            if (character == '\0')
            {
                if (builder.Length > 0) { yield return builder.ToString(); builder.Clear(); }
            }
            else if (char.IsControl(character)) builder.Clear();
            else if (builder.Length < 1024) builder.Append(character);
        }
        if (builder.Length > 0) yield return builder.ToString();
    }

    private static bool TryFileTime(long ticks, out DateTimeOffset when)
    {
        try
        {
            var candidate = new DateTimeOffset(DateTime.FromFileTimeUtc(ticks), TimeSpan.Zero);
            when = candidate;
            return candidate.Year is >= 1995 and <= 2200;
        }
        catch (ArgumentOutOfRangeException) { when = default; return false; }
    }

    private static async Task<byte[]> ReadBounded(string path, CancellationToken token)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, true);
        var length = (int)Math.Min(stream.Length, MaxInspectionBytes);
        var data = new byte[length];
        var offset = 0;
        while (offset < length) { var read = await stream.ReadAsync(data.AsMemory(offset), token); if (read == 0) break; offset += read; }
        return offset == length ? data : data[..offset];
    }

    private static uint ReadUInt32(byte[] data, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset, 4));
    private static ulong ReadUInt64(byte[] data, int offset) => BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(offset, 8));
    private static void Add(AnalyzerOutput output, AnalyzerContext context, ArtifactKind kind, string name, string value, string detail, ConfidenceLevel confidence = ConfidenceLevel.Observed) => output.Artifacts.Add(new AnalysisArtifact { EvidenceId = context.Evidence.Id, AnalysisRunId = context.AnalysisRunId, Kind = kind, Name = name, Value = value, Context = detail, Confidence = confidence });
}

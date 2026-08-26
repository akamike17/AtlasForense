using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using AtlasForense.Models;

namespace AtlasForense.Forensics;

public sealed class EvtxStructureAnalyzer : IForensicAnalyzer
{
    private const int MaxInspectionBytes = 64 * 1024 * 1024;
    private const int ChunkSize = 64 * 1024;
    private const int MaxRecordsPerChunk = 100_000;
    private const int MaxStrings = 400;
    private const int MaxChunks = 1_024;
    public string Id => "windows-evtx-structure";
    public string Version => "1.0.0";

    public bool CanAnalyze(EvidenceItem evidence) =>
        Path.GetExtension(evidence.OriginalFileName).Equals(".evtx", StringComparison.OrdinalIgnoreCase) ||
        evidence.DetectedFileType.Equals("EVTX", StringComparison.OrdinalIgnoreCase);

    public async Task<AnalyzerOutput> AnalyzeAsync(AnalyzerContext context)
    {
        var data = await ReadBounded(context.FilePath, context.CancellationToken);
        var output = new AnalyzerOutput();
        if (data.Length < 4096 || !data.AsSpan(0, 8).SequenceEqual("ElfFile\0"u8))
            throw new InvalidDataException("La evidencia no contiene una cabecera ElfFile válida de EVTX.");

        var headerSize = ReadUInt32(data, 32);
        var minor = ReadUInt32(data, 36);
        var major = ReadUInt32(data, 40);
        var blockSize = ReadUInt32(data, 44);
        var declaredChunks = ReadUInt32(data, 48);
        Add(output, context, ArtifactKind.Metadata, "Cabecera EVTX", $"v{major}.{minor}", $"headerSize={headerSize}; blockSize={blockSize}; chunksDeclarados={declaredChunks}");

        var totalRecords = 0;
        var damagedChunks = 0;
        long? firstTimestamp = null;
        long? lastTimestamp = null;
        var strings = new HashSet<string>(StringComparer.Ordinal);
        var chunksScanned = 0;
        for (var index = 0; index < MaxChunks; index++)
        {
            context.CancellationToken.ThrowIfCancellationRequested();
            var chunkStart = 4096 + index * ChunkSize;
            if (chunkStart >= data.Length) break;
            chunksScanned++;
            var available = Math.Min(ChunkSize, data.Length - chunkStart);
            if (available < 512 || !data.AsSpan(chunkStart, 8).SequenceEqual("ElfChnk\0"u8))
            {
                damagedChunks++;
                Add(output, context, ArtifactKind.Capability, "Chunk EVTX dañado o ausente", $"chunk {index}", "Falta la firma ElfChnk; el registro puede estar truncado o alterado.", ConfidenceLevel.Inferred);
                continue;
            }

            var firstRecord = ReadUInt64(data, chunkStart + 8);
            var lastRecord = ReadUInt64(data, chunkStart + 16);
            var firstOffset = ReadUInt32(data, chunkStart + 24);
            var lastOffset = ReadUInt32(data, chunkStart + 28);
            if (lastRecord < firstRecord)
                Add(output, context, ArtifactKind.Capability, "Numeración de registros inconsistente", $"chunk {index}", $"primer={firstRecord}; último={lastRecord}; puede indicar edición manual del registro", ConfidenceLevel.Inferred);

            var records = 0;
            var offset = firstOffset >= 512 ? firstOffset : 512u;
            while (records < MaxRecordsPerChunk && offset + 24 <= available)
            {
                var absolute = chunkStart + (int)offset;
                var magic = ReadUInt32(data, absolute);
                var size = ReadUInt32(data, absolute + 4);
                if (magic != 0x2a2a) break;
                if (size < 24 || size > ChunkSize) break;
                records++;
                totalRecords++;
                var ticks = (long)ReadUInt64(data, absolute + 16);
                if (ticks is > 0 and < 2650467744000000000)
                {
                    firstTimestamp = firstTimestamp is null ? ticks : Math.Min(firstTimestamp.Value, ticks);
                    lastTimestamp = lastTimestamp is null ? ticks : Math.Max(lastTimestamp.Value, ticks);
                }
                if (strings.Count < MaxStrings) CollectStrings(data, absolute + 24, (int)Math.Min(size - 24, 4096), strings);
                if (offset + 24 >= lastOffset && offset + size > lastOffset) break;
                offset += size;
            }
            Add(output, context, ArtifactKind.Metadata, "Chunk EVTX", $"chunk {index}", $"registros={records}; primero={firstRecord}; último={lastRecord}");
        }

        if (chunksScanned == 0)
            throw new InvalidDataException("Ningún chunk EVTX presente; el archivo está truncado o no es un registro de eventos válido.");

        if (firstTimestamp.HasValue && TryFileTime(firstTimestamp.Value, out var firstEvent))
            output.Events.Add(new TimelineEvent { EvidenceId = context.Evidence.Id, OccurredAtUtc = firstEvent, Category = "EVTX", Title = "Primer registro con marca de tiempo", Description = "Timestamp FILETIME declarado en el primer registro observable.", Source = $"{context.Evidence.Identifier}/evtx-records", Confidence = ConfidenceLevel.Observed });
        if (lastTimestamp.HasValue && TryFileTime(lastTimestamp.Value, out var lastEvent))
            output.Events.Add(new TimelineEvent { EvidenceId = context.Evidence.Id, OccurredAtUtc = lastEvent, Category = "EVTX", Title = "Último registro con marca de tiempo", Description = "Timestamp FILETIME declarado en el último registro observable.", Source = $"{context.Evidence.Identifier}/evtx-records", Confidence = ConfidenceLevel.Observed });

        foreach (var value in strings)
            Add(output, context, ArtifactKind.String, "Cadena UTF-16", value, "Cadena imprimible observada en BinXml sin decodificación completa de plantilla.", ConfidenceLevel.Observed);

        var truncated = data.Length >= MaxInspectionBytes ? "; inspección limitada a 64 MB" : string.Empty;
        output.Summary = $"EVTX estático: {chunksScanned} chunk(s) explorado(s), {totalRecords} registro(s), {strings.Count} cadena(s), {damagedChunks} chunk(s) dañado(s){truncated}; BinXml no decodizado por completo; muestra no ejecutada.";
        return output;
    }

    private static void CollectStrings(byte[] data, int offset, int length, HashSet<string> sink)
    {
        var builder = new StringBuilder();
        for (var index = 0; index + 1 < length && sink.Count < MaxStrings; index += 2)
        {
            var character = (char)(data[offset + index] | (data[offset + index + 1] << 8));
            if (character is >= ' ' and <= '~') builder.Append(character);
            else if (builder.Length >= 6)
            {
                sink.Add(builder.ToString());
                builder.Clear();
            }
            else builder.Clear();
        }
        if (builder.Length >= 6 && sink.Count < MaxStrings) sink.Add(builder.ToString());
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

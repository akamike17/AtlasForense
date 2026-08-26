using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using AtlasForense.Models;

namespace AtlasForense.Forensics;

public sealed class RegistryHiveAnalyzer : IForensicAnalyzer
{
    private const int MaxInspectionBytes = 64 * 1024 * 1024;
    private const int HeaderSize = 4096;
    private const int MaxKeyNodes = 1_500;
    private const int MaxKeyArtifacts = 400;
    private const int MaxValueArtifacts = 600;
    private const int MaxListEntries = 4_096;
    private static readonly string[] KnownHiveNames = ["NTUSER.DAT", "USRCLASS.DAT", "SOFTWARE", "SYSTEM", "SAM", "SECURITY", "DEFAULT", "COMPONENTS", "DRIVERS"];
    public string Id => "windows-registry-hive";
    public string Version => "1.0.0";

    public bool CanAnalyze(EvidenceItem evidence)
    {
        if (evidence.DetectedFileType.Equals("REGF", StringComparison.OrdinalIgnoreCase)) return true;
        var fileName = Path.GetFileName(evidence.OriginalFileName);
        return KnownHiveNames.Contains(fileName, StringComparer.OrdinalIgnoreCase) ||
               Path.GetExtension(fileName).Equals(".hiv", StringComparison.OrdinalIgnoreCase);
    }

    public async Task<AnalyzerOutput> AnalyzeAsync(AnalyzerContext context)
    {
        var data = await ReadBounded(context.FilePath, context.CancellationToken);
        var output = new AnalyzerOutput();
        if (data.Length < HeaderSize || !data.AsSpan(0, 4).SequenceEqual("regf"u8))
            throw new InvalidDataException("La evidencia no contiene una cabecera regf válida de colmena de registro.");

        var sequenceA = ReadUInt32(data, 4);
        var sequenceB = ReadUInt32(data, 8);
        var major = ReadUInt32(data, 20);
        var minor = ReadUInt32(data, 24);
        var rootCell = ReadUInt32(data, 36);
        var hiveName = ReadUtf16Fixed(data, 48, 64);
        Add(output, context, ArtifactKind.Metadata, "Colmena de registro", string.IsNullOrWhiteSpace(hiveName) ? "<sin nombre>" : hiveName, $"formato={major}.{minor}; secuencias={sequenceA}/{sequenceB}");
        if (sequenceA != sequenceB)
            Add(output, context, ArtifactKind.Capability, "Secuencias de transacción divergentes", $"primaria={sequenceA}; secundaria={sequenceB}", "Las secuencias difieren; la colmena pudo quedar inconsistente o editada fuera de línea.", ConfidenceLevel.Inferred);

        if (TryFileTime((long)ReadUInt64(data, 12), out var writtenAt))
            output.Events.Add(new TimelineEvent { EvidenceId = context.Evidence.Id, OccurredAtUtc = writtenAt, Category = "Registro", Title = "Última escritura declarada de la colmena", Description = "Marca FILETIME declarada en la cabecera regf.", Source = $"{context.Evidence.Identifier}/hive-header", Confidence = ConfidenceLevel.Inferred });

        if (data.Length < HeaderSize + 4 || !data.AsSpan(HeaderSize, 4).SequenceEqual("hbin"u8))
            throw new InvalidDataException("El primer bloque hbin no está presente; la colmena está truncada o corrupta.");

        var visited = 0;
        var keyArtifacts = 0;
        var valueArtifacts = 0;
        var queue = new Queue<(uint Offset, string Path)>();
        queue.Enqueue((rootCell, string.Empty));
        while (queue.Count > 0 && visited < MaxKeyNodes)
        {
            context.CancellationToken.ThrowIfCancellationRequested();
            var (offset, parentPath) = queue.Dequeue();
            var key = ReadCell(data, offset);
            if (key < 0 || key + 0x4c > data.Length || data[key] != (byte)'n' || data[key + 1] != (byte)'k') continue;
            visited++;

            var flags = ReadUInt16(data, key + 2);
            var nameLength = ReadUInt16(data, key + 0x48);
            var name = ReadKeyName(data, key + 0x4c, nameLength, (flags & 0x0020) != 0);
            var path = parentPath.Length == 0 ? name : $"{parentPath}\\{name}";
            if (keyArtifacts < MaxKeyArtifacts)
            {
                keyArtifacts++;
                var subkeys = ReadUInt32(data, key + 0x14);
                var values = ReadUInt32(data, key + 0x24);
                Add(output, context, ArtifactKind.Metadata, "Clave de registro", path, $"subclaves={subkeys}; valores={values}");
            }
            if (parentPath.Length == 0 && TryFileTime((long)ReadUInt64(data, key + 4), out var keyStamp))
                output.Events.Add(new TimelineEvent { EvidenceId = context.Evidence.Id, OccurredAtUtc = keyStamp, Category = "Registro", Title = "Última escritura declarada de la clave raíz", Description = "Marca FILETIME declarada en el nodo nk raíz.", Source = $"{context.Evidence.Identifier}/nk-root", Confidence = ConfidenceLevel.Inferred });

            valueArtifacts = ReadValues(data, key, path, output, context, valueArtifacts);

            var subkeyList = ReadUInt32(data, key + 0x1c);
            foreach (var child in ReadSubkeyOffsets(data, subkeyList))
            {
                if (visited + queue.Count >= MaxKeyNodes) break;
                queue.Enqueue((child, path));
            }
        }

        output.Summary = $"Colmena estática: {visited} nodo(s) de clave recorridos, {keyArtifacts} clave(s) y {valueArtifacts} valor(es) documentados; recorrido acotado sin decodificar listas volátiles; muestra no ejecutada.";
        return output;
    }

    private static int ReadValues(byte[] data, int key, string path, AnalyzerOutput output, AnalyzerContext context, int valueArtifacts)
    {
        var count = ReadUInt32(data, key + 0x24);
        var listOffset = ReadUInt32(data, key + 0x28);
        if (count == 0 || count > MaxListEntries || listOffset == 0xffffffff) return valueArtifacts;
        var list = ReadCell(data, listOffset);
        if (list < 0 || list + 4 * count > data.Length) return valueArtifacts;
        for (var index = 0; index < count && valueArtifacts < MaxValueArtifacts; index++)
        {
            var valueOffset = ReadUInt32(data, list + index * 4);
            var value = ReadCell(data, valueOffset);
            if (value < 0 || value + 0x14 > data.Length || data[value] != (byte)'v' || data[value + 1] != (byte)'k') continue;
            var nameLength = ReadUInt16(data, value + 2);
            var dataSize = ReadUInt32(data, value + 4);
            var dataOffset = ReadUInt32(data, value + 8);
            var type = ReadUInt32(data, value + 12);
            var valueFlags = ReadUInt16(data, value + 16);
            var valueName = nameLength == 0 ? "(predeterminado)" : ReadKeyName(data, value + 0x14, nameLength, (valueFlags & 0x0001) != 0);
            valueArtifacts++;
            var detail = $"tipo={ValueTypeName(type)}; tamaño={dataSize & 0x7fffffff}";
            var rendered = RenderValue(data, type, dataSize, dataOffset);
            if (rendered is not null) detail += $"; dato={rendered}";
            Add(output, context, ArtifactKind.Metadata, "Valor de registro", $"{path}\\{valueName}", detail);
        }
        return valueArtifacts;
    }

    private static string? RenderValue(byte[] data, uint type, uint rawSize, uint dataOffset)
    {
        var size = rawSize & 0x7fffffff;
        if (size == 0 || size > 512) return null;
        if ((rawSize & 0x80000000) != 0)
        {
            var resident = BitConverter.GetBytes(dataOffset);
            return type == 4 ? BinaryPrimitives.ReadUInt32LittleEndian(resident).ToString(CultureInfo.InvariantCulture) : Convert.ToHexString(resident.AsSpan(0, (int)Math.Min(size, 4)));
        }
        var payload = ReadCell(data, dataOffset);
        if (payload < 0 || payload + size > data.Length) return null;
        if (type == 4) return size >= 4 ? BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(payload, 4)).ToString(CultureInfo.InvariantCulture) : null;
        if (type == 11) return size >= 8 ? BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(payload, 8)).ToString(CultureInfo.InvariantCulture) : null;
        if (type is 1 or 2 or 7)
        {
            var text = Encoding.Unicode.GetString(data, payload, (int)size).TrimEnd('\0');
            return text.Length > 256 ? text[..256] + "…" : text;
        }
        return Convert.ToHexString(data.AsSpan(payload, (int)Math.Min(size, 32)));
    }

    private static IEnumerable<uint> ReadSubkeyOffsets(byte[] data, uint listOffset)
    {
        if (listOffset == 0 || listOffset == 0xffffffff) yield break;
        var list = ReadCell(data, listOffset);
        if (list < 0 || list + 4 > data.Length) yield break;
        var signature = (char)data[list] + "" + (char)data[list + 1];
        var count = ReadUInt16(data, list + 2);
        if (count > MaxListEntries) yield break;
        if (signature == "ri")
        {
            if (list + 4 + 4 * count > data.Length) yield break;
            for (var index = 0; index < count; index++)
                foreach (var child in ReadSubkeyOffsets(data, ReadUInt32(data, list + 4 + index * 4)))
                    yield return child;
            yield break;
        }
        if (signature is not ("lf" or "lh")) yield break;
        if (list + 4 + 8 * count > data.Length) yield break;
        for (var index = 0; index < count; index++)
            yield return ReadUInt32(data, list + 4 + index * 8);
    }

    private static int ReadCell(byte[] data, uint offset)
    {
        var absolute = (long)HeaderSize + offset;
        if (offset == 0 || offset == 0xffffffff || absolute < 0 || absolute + 4 > data.Length) return -1;
        var size = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan((int)absolute, 4));
        if (size >= 0) return -1;
        return (int)absolute + 4;
    }

    private static string ReadKeyName(byte[] data, int offset, int length, bool ascii)
    {
        if (length <= 0 || length > 512 || offset < 0 || offset + length > data.Length) return "<nombre ilegible>";
        if (ascii) return Sanitize(Encoding.ASCII.GetString(data, offset, length));
        if (length % 2 == 0 && offset + length <= data.Length) return Sanitize(Encoding.Unicode.GetString(data, offset, length));
        return Sanitize(Encoding.ASCII.GetString(data, offset, length));
    }

    private static string Sanitize(string value)
    {
        var builder = new StringBuilder(value.Length);
        foreach (var character in value) builder.Append(character is >= ' ' and <= '~' ? character : '?');
        var result = builder.ToString().TrimEnd('\0');
        return result.Length == 0 ? "<sin nombre>" : result;
    }

    private static string ReadUtf16Fixed(byte[] data, int offset, int length)
    {
        var end = length;
        for (var index = 0; index + 1 < length; index += 2)
            if (data[offset + index] == 0 && data[offset + index + 1] == 0) { end = index; break; }
        return end == 0 ? string.Empty : Encoding.Unicode.GetString(data, offset, end).TrimEnd('\0');
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

    private static string ValueTypeName(uint type) => type switch { 0 => "REG_NONE", 1 => "REG_SZ", 2 => "REG_EXPAND_SZ", 3 => "REG_BINARY", 4 => "REG_DWORD", 5 => "REG_DWORD_BIG_ENDIAN", 6 => "REG_LINK", 7 => "REG_MULTI_SZ", 8 => "REG_RESOURCE_LIST", 11 => "REG_QWORD", _ => $"0x{type:X8}" };

    private static async Task<byte[]> ReadBounded(string path, CancellationToken token)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, true);
        var length = (int)Math.Min(stream.Length, MaxInspectionBytes);
        var data = new byte[length];
        var offset = 0;
        while (offset < length) { var read = await stream.ReadAsync(data.AsMemory(offset), token); if (read == 0) break; offset += read; }
        return offset == length ? data : data[..offset];
    }

    private static ushort ReadUInt16(byte[] data, int offset) => BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(offset, 2));
    private static uint ReadUInt32(byte[] data, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset, 4));
    private static ulong ReadUInt64(byte[] data, int offset) => BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(offset, 8));
    private static void Add(AnalyzerOutput output, AnalyzerContext context, ArtifactKind kind, string name, string value, string detail, ConfidenceLevel confidence = ConfidenceLevel.Observed) => output.Artifacts.Add(new AnalysisArtifact { EvidenceId = context.Evidence.Id, AnalysisRunId = context.AnalysisRunId, Kind = kind, Name = name, Value = value, Context = detail, Confidence = confidence });
}

using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using AtlasForense.Models;

namespace AtlasForense.Forensics;

public sealed class WindowsShortcutAnalyzer : IForensicAnalyzer
{
    private const int MaxBytes = 16 * 1024 * 1024;
    private static ReadOnlySpan<byte> ShellLinkClsid => [0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46];
    public string Id => "windows-shell-link";
    public string Version => "1.0.0";
    public bool CanAnalyze(EvidenceItem evidence) => Path.GetExtension(evidence.OriginalFileName).Equals(".lnk", StringComparison.OrdinalIgnoreCase);

    public async Task<AnalyzerOutput> AnalyzeAsync(AnalyzerContext context)
    {
        var info = new FileInfo(context.FilePath);
        if (info.Length > MaxBytes) throw new InvalidDataException($"El acceso directo excede el límite de {MaxBytes} bytes.");
        var data = await File.ReadAllBytesAsync(context.FilePath, context.CancellationToken);
        if (data.Length < 76 || ReadUInt32(data, 0) != 0x4c || !data.AsSpan(4, 16).SequenceEqual(ShellLinkClsid))
            throw new InvalidDataException("La cabecera Shell Link es inválida o está truncada.");
        var output = new AnalyzerOutput();
        var flags = ReadUInt32(data, 20);
        var attributes = ReadUInt32(data, 24);
        Add(output, context, ArtifactKind.Metadata, "Flags Shell Link", $"0x{flags:X8}", DescribeFlags(flags));
        Add(output, context, ArtifactKind.Metadata, "Atributos del destino", $"0x{attributes:X8}", DescribeAttributes(attributes));
        Add(output, context, ArtifactKind.Metadata, "Tamaño declarado del destino", ReadUInt32(data, 52).ToString(CultureInfo.InvariantCulture), "bytes; valor almacenado en la cabecera del enlace");
        AddFileTime(output, context, "Creación del destino", data, 28);
        AddFileTime(output, context, "Acceso al destino", data, 36);
        AddFileTime(output, context, "Modificación del destino", data, 44);

        var offset = 76;
        if ((flags & 0x1) != 0)
        {
            Require(data, offset, 2, "LinkTargetIDList");
            var size = ReadUInt16(data, offset); offset += 2;
            Require(data, offset, size, "LinkTargetIDList"); offset += size;
        }
        if ((flags & 0x2) != 0)
        {
            Require(data, offset, 4, "LinkInfo");
            var size = checked((int)ReadUInt32(data, offset));
            if (size < 0x1c) throw new InvalidDataException("LinkInfo declara un tamaño inválido.");
            Require(data, offset, size, "LinkInfo");
            ReadLinkInfo(data, offset, size, output, context);
            offset += size;
        }
        var unicode = (flags & 0x80) != 0;
        var fields = new[] { (Bit: 0x4u, Name: "Descripción"), (Bit: 0x8u, Name: "Ruta relativa"), (Bit: 0x10u, Name: "Directorio de trabajo"), (Bit: 0x20u, Name: "Argumentos"), (Bit: 0x40u, Name: "Ubicación de icono") };
        foreach (var field in fields)
        {
            if ((flags & field.Bit) == 0) continue;
            var value = ReadCountedString(data, ref offset, unicode, field.Name);
            Add(output, context, field.Name is "Ruta relativa" or "Directorio de trabajo" ? ArtifactKind.Metadata : ArtifactKind.String, field.Name, value, unicode ? "StringData UTF-16LE" : "StringData de página de códigos no declarada; representada como Latin-1");
            if (field.Name == "Argumentos") AddArgumentCapabilities(output, context, value);
            if (field.Name == "Ruta relativa") AddPathEntity(output, context, value);
        }
        output.Summary = $"Shell Link estático: flags 0x{flags:X8}, {output.Artifacts.Count} artefacto(s), {output.Events.Count} tiempo(s); enlace no resuelto ni ejecutado.";
        return output;
    }

    private static void ReadLinkInfo(byte[] data, int start, int size, AnalyzerOutput output, AnalyzerContext context)
    {
        var headerSize = checked((int)ReadUInt32(data, start + 4));
        if (headerSize < 0x1c || headerSize > size) throw new InvalidDataException("LinkInfoHeaderSize es inválido.");
        var localOffset = ReadUInt32(data, start + 16);
        var suffixOffset = ReadUInt32(data, start + 24);
        var localUnicodeOffset = headerSize >= 0x24 ? ReadUInt32(data, start + 28) : 0;
        var suffixUnicodeOffset = headerSize >= 0x24 ? ReadUInt32(data, start + 32) : 0;
        var local = localUnicodeOffset > 0 ? ReadNullString(data, start, size, localUnicodeOffset, true) : ReadNullString(data, start, size, localOffset, false);
        var suffix = suffixUnicodeOffset > 0 ? ReadNullString(data, start, size, suffixUnicodeOffset, true) : ReadNullString(data, start, size, suffixOffset, false);
        if (!string.IsNullOrWhiteSpace(local)) { Add(output, context, ArtifactKind.Metadata, "Ruta base local", local, "LinkInfo"); AddPathEntity(output, context, local); }
        if (!string.IsNullOrWhiteSpace(suffix)) Add(output, context, ArtifactKind.Metadata, "Sufijo de ruta", suffix, "LinkInfo");
    }

    private static string ReadCountedString(byte[] data, ref int offset, bool unicode, string name)
    {
        Require(data, offset, 2, name);
        var characters = ReadUInt16(data, offset); offset += 2;
        var bytes = checked(characters * (unicode ? 2 : 1));
        if (characters > 32_768) throw new InvalidDataException($"{name} excede el límite de caracteres.");
        Require(data, offset, bytes, name);
        var value = unicode ? Encoding.Unicode.GetString(data, offset, bytes) : Encoding.Latin1.GetString(data, offset, bytes);
        offset += bytes;
        return value.TrimEnd('\0');
    }

    private static string ReadNullString(byte[] data, int blockStart, int blockSize, uint relativeOffset, bool unicode)
    {
        if (relativeOffset == 0 || relativeOffset >= blockSize) return string.Empty;
        var start = checked(blockStart + (int)relativeOffset);
        var end = blockStart + blockSize;
        var cursor = start;
        if (unicode)
        {
            while (cursor <= end - 2 && (data[cursor] != 0 || data[cursor + 1] != 0)) cursor += 2;
            return cursor <= end - 2 ? Encoding.Unicode.GetString(data, start, cursor - start) : string.Empty;
        }
        while (cursor < end && data[cursor] != 0) cursor++;
        return cursor < end ? Encoding.Latin1.GetString(data, start, cursor - start) : string.Empty;
    }

    private static void AddFileTime(AnalyzerOutput output, AnalyzerContext context, string name, byte[] data, int offset)
    {
        var raw = BinaryPrimitives.ReadInt64LittleEndian(data.AsSpan(offset, 8));
        if (raw <= 0) return;
        try
        {
            var time = DateTimeOffset.FromFileTime(raw);
            if (time.Year is < 1993 or > 2200) return;
            Add(output, context, ArtifactKind.Metadata, name, time.ToString("O"), $"FILETIME={raw}");
            output.Events.Add(new TimelineEvent { EvidenceId = context.Evidence.Id, OccurredAtUtc = time, Category = "Shell Link", Title = name, Description = "Timestamp del destino almacenado en la cabecera .lnk; puede estar obsoleto o manipulado.", Source = $"{context.Evidence.Identifier}/shell-link", Confidence = ConfidenceLevel.Inferred });
        }
        catch (ArgumentOutOfRangeException) { }
    }

    private static void AddArgumentCapabilities(AnalyzerOutput output, AnalyzerContext context, string arguments)
    {
        var patterns = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            ["PowerShell con contenido codificado"] = ["-enc ", "-encodedcommand"],
            ["Ejecución mediante intérprete"] = ["cmd /c", "powershell", "pwsh"],
            ["Carga mediante utilidad del sistema"] = ["rundll32", "regsvr32", "mshta"],
            ["Descarga o transferencia"] = ["http://", "https://", "bitsadmin", "certutil"]
        };
        foreach (var pattern in patterns)
        {
            var observed = pattern.Value.Where(x => arguments.Contains(x, StringComparison.OrdinalIgnoreCase)).ToArray();
            if (observed.Length > 0) Add(output, context, ArtifactKind.Capability, "Patrón de argumentos", pattern.Key, $"coincidencias={string.Join(", ", observed)}; requiere interpretación humana", ConfidenceLevel.Inferred);
        }
    }

    private static void AddPathEntity(AnalyzerOutput output, AnalyzerContext context, string path)
    {
        if (string.IsNullOrWhiteSpace(path) || output.Entities.Any(x => x.Type == "FilePath" && x.Value.Equals(path, StringComparison.OrdinalIgnoreCase))) return;
        output.Entities.Add(new CaseEntity { Type = "FilePath", Value = path, DisplayName = path, Confidence = ConfidenceLevel.Observed, EvidenceIds = [context.Evidence.Id] });
    }

    private static string DescribeFlags(uint value) => $"targetIdList={(value & 1) != 0}; linkInfo={(value & 2) != 0}; unicode={(value & 0x80) != 0}; argumentos={(value & 0x20) != 0}; directorioTrabajo={(value & 0x10) != 0}";
    private static string DescribeAttributes(uint value) => $"soloLectura={(value & 1) != 0}; oculto={(value & 2) != 0}; sistema={(value & 4) != 0}; directorio={(value & 0x10) != 0}; archivo={(value & 0x20) != 0}";
    private static void Require(byte[] data, int offset, int length, string structure) { if (offset < 0 || length < 0 || offset > data.Length - length) throw new InvalidDataException($"{structure} queda fuera del archivo."); }
    private static ushort ReadUInt16(byte[] data, int offset) => BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(offset, 2));
    private static uint ReadUInt32(byte[] data, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset, 4));
    private static void Add(AnalyzerOutput output, AnalyzerContext context, ArtifactKind kind, string name, string value, string detail, ConfidenceLevel confidence = ConfidenceLevel.Observed) => output.Artifacts.Add(new AnalysisArtifact { EvidenceId = context.Evidence.Id, AnalysisRunId = context.AnalysisRunId, Kind = kind, Name = name, Value = value, Context = detail, Confidence = confidence });
}

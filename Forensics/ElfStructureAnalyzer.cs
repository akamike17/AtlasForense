using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using AtlasForense.Models;

namespace AtlasForense.Forensics;

public sealed class ElfStructureAnalyzer : IForensicAnalyzer
{
    private const int MaxInspectionBytes = 64 * 1024 * 1024;
    private const int MaxHeaders = 256;
    private const int MaxDynamicEntries = 4_096;
    private static readonly string[] Extensions = [".elf", ".so", ".axf", ".o"];
    public string Id => "linux-elf-structure";
    public string Version => "1.0.0";

    public bool CanAnalyze(EvidenceItem evidence) =>
        Extensions.Contains(Path.GetExtension(evidence.OriginalFileName), StringComparer.OrdinalIgnoreCase) ||
        evidence.DetectedFileType.Equals("ELF", StringComparison.OrdinalIgnoreCase);

    public async Task<AnalyzerOutput> AnalyzeAsync(AnalyzerContext context)
    {
        var data = await ReadBounded(context.FilePath, context.CancellationToken);
        var output = new AnalyzerOutput();
        if (data.Length < 52 || data[0] != 0x7f || data[1] != (byte)'E' || data[2] != (byte)'L' || data[3] != (byte)'F')
            throw new InvalidDataException("La evidencia no contiene una cabecera ELF válida.");

        var elfClass = data[4];
        var encoding = data[5];
        if (elfClass is not (1 or 2)) throw new InvalidDataException("La clase ELF declarada no es de 32 ni de 64 bits.");
        if (encoding is not (1 or 2)) throw new InvalidDataException("La codificación de enteros ELF declarada no está soportada.");
        var is64 = elfClass == 2;
        var bigEndian = encoding == 2;
        var headerSize = is64 ? 64 : 52;
        if (data.Length < headerSize) throw new InvalidDataException("La cabecera ELF está truncada.");

        var type = ReadUInt16(data, 16, bigEndian);
        var machine = ReadUInt16(data, 18, bigEndian);
        var entry = is64 ? ReadUInt64(data, 24, bigEndian) : ReadUInt32(data, 24, bigEndian);
        var phoff = (long)(is64 ? ReadUInt64(data, 32, bigEndian) : ReadUInt32(data, 28, bigEndian));
        var shoff = (long)(is64 ? ReadUInt64(data, 40, bigEndian) : ReadUInt32(data, 32, bigEndian));
        var phentsize = ReadUInt16(data, is64 ? 54 : 42, bigEndian);
        var phnum = ReadUInt16(data, is64 ? 56 : 44, bigEndian);
        var shentsize = ReadUInt16(data, is64 ? 58 : 46, bigEndian);
        var shnum = ReadUInt16(data, is64 ? 60 : 48, bigEndian);
        var shstrndx = ReadUInt16(data, is64 ? 62 : 50, bigEndian);

        Add(output, context, ArtifactKind.Metadata, "Clase ELF", is64 ? "ELF64" : "ELF32", $"class={elfClass}; data={(bigEndian ? "big-endian" : "little-endian")}; osabi={data[7]}");
        Add(output, context, ArtifactKind.Metadata, "Tipo ELF", TypeName(type), $"type=0x{type:X4}");
        Add(output, context, ArtifactKind.Metadata, "Arquitectura ELF", MachineName(machine), $"machine=0x{machine:X4}");
        Add(output, context, ArtifactKind.Metadata, "Punto de entrada ELF", $"0x{entry:X}", "Valor declarado en la cabecera; no implica ejecución.");

        var rwxSegments = 0;
        if (phnum > MaxHeaders || shnum > MaxHeaders) throw new InvalidDataException("El número de cabeceras de programa o de sección excede el límite de inspección.");
        var phSize = is64 ? 56 : 32;
        if (phnum > 0 && phentsize < phSize) throw new InvalidDataException("El tamaño declarado de las cabeceras de programa ELF no es válido.");
        for (var index = 0; index < phnum; index++)
        {
            var offset = phoff + (long)index * phentsize;
            if (phoff <= 0 || offset > data.Length - phSize) throw new InvalidDataException("La tabla de cabeceras de programa ELF queda fuera del límite de inspección.");
            var pType = ReadUInt32(data, (int)offset, bigEndian);
            var flags = ReadUInt32(data, (int)offset + (is64 ? 4 : 24), bigEndian);
            var permissions = $"{((flags & 4) != 0 ? "R" : "-")}{((flags & 2) != 0 ? "W" : "-")}{((flags & 1) != 0 ? "X" : "-")}";
            if (pType == 1)
            {
                Add(output, context, ArtifactKind.Metadata, "Segmento LOAD", $"segmento {index}", $"permisos={permissions}; flags=0x{flags:X}");
                if (flags == 7)
                {
                    rwxSegments++;
                    Add(output, context, ArtifactKind.Capability, "Segmento RWX", $"segmento {index}", "Segmento cargable con lectura, escritura y ejecución simultáneas; revisar empaquetado o código automodificable", ConfidenceLevel.Inferred);
                }
            }
            else if (pType is 2 or 3) Add(output, context, ArtifactKind.Metadata, pType == 2 ? "Segmento DYNAMIC" : "Segmento INTERP", $"segmento {index}", $"permisos={permissions}");
        }

        var shSize = is64 ? 64 : 40;
        if (shnum > 0 && shentsize < shSize) throw new InvalidDataException("El tamaño declarado de las cabeceras de sección ELF no es válido.");
        var sections = new List<ElfSection>();
        var highEntropy = 0;
        var suspicious = 0;
        if (shnum > 0)
        {
            if (shoff <= 0 || shoff > data.Length - shnum * (long)shentsize) throw new InvalidDataException("La tabla de secciones ELF queda fuera del límite de inspección.");
            var strtab = shstrndx < shnum ? ReadSection(data, (int)(shoff + shstrndx * (long)shentsize), is64, bigEndian) : null;
            for (var index = 0; index < shnum; index++)
            {
                var section = ReadSection(data, (int)(shoff + index * (long)shentsize), is64, bigEndian);
                var name = ResolveName(data, strtab, section.NameIndex);
                sections.Add(section with { ResolvedName = name });
                var entropy = SectionEntropy(data, section.Offset, section.Size);
                var entropyText = entropy.HasValue ? entropy.Value.ToString("F4", CultureInfo.InvariantCulture) : "no muestreada";
                Add(output, context, ArtifactKind.Metadata, "Sección ELF", name, $"tipo={SectionTypeName(section.Type)}; offset=0x{section.Offset:X}; tamaño={section.Size}; entropía={entropyText}");
                if (entropy is >= 7.2 && section.Size >= 256)
                {
                    highEntropy++;
                    Add(output, context, ArtifactKind.Entropy, "Alta entropía de sección", name, entropyText, ConfidenceLevel.Inferred);
                }
                if (IsSuspiciousSectionName(name))
                {
                    suspicious++;
                    Add(output, context, ArtifactKind.Capability, "Nombre de sección inusual", name, "Nombre asociado habitualmente a empaquetadores o alteración manual", ConfidenceLevel.Inferred);
                }
            }
        }

        var libraries = ReadNeededLibraries(data, bigEndian, is64, sections);
        foreach (var library in libraries)
        {
            Add(output, context, ArtifactKind.Metadata, "Biblioteca dinámica", library, "DT_NEEDED declarado en el segmento dinámico");
            if (!output.Entities.Any(x => x.Type == "Module" && x.Value.Equals(library, StringComparison.OrdinalIgnoreCase)))
                output.Entities.Add(new CaseEntity { Type = "Module", Value = library.ToLowerInvariant(), DisplayName = library, Confidence = ConfidenceLevel.Observed, EvidenceIds = [context.Evidence.Id] });
        }

        output.Summary = $"ELF estático: {TypeName(type)}, {(is64 ? "64" : "32")} bits {(bigEndian ? "big-endian" : "little-endian")}, {MachineName(machine)}, {phnum} segmento(s), {shnum} sección(es), {libraries.Count} biblioteca(s) DT_NEEDED, {rwxSegments} segmento(s) RWX, {highEntropy} con alta entropía; muestra no cargada ni ejecutada.";
        return output;
    }

    private static List<string> ReadNeededLibraries(byte[] data, bool bigEndian, bool is64, IReadOnlyList<ElfSection> sections)
    {
        var result = new List<string>();
        var dynamic = sections.FirstOrDefault(x => x.Type == 6);
        var strtab = sections.FirstOrDefault(x => x.Type == 3);
        if (dynamic is null || strtab is null || dynamic.Offset <= 0 || dynamic.Offset >= data.Length) return result;
        var entrySize = is64 ? 16 : 8;
        var count = (int)Math.Min(MaxDynamicEntries, dynamic.Size / entrySize);
        if (dynamic.Offset > data.Length - count * entrySize) return result;
        for (var index = 0; index < count; index++)
        {
            var offset = (int)dynamic.Offset + index * entrySize;
            var tag = is64 ? (long)ReadUInt64(data, offset, bigEndian) : ReadInt32(data, offset, bigEndian);
            if (tag == 0) break;
            if (tag != 1) continue;
            var value = is64 ? (ulong)ReadUInt64(data, offset + 8, bigEndian) : ReadUInt32(data, offset + 4, bigEndian);
            if (value >= (ulong)int.MaxValue || value >= (ulong)strtab.Size) continue;
            var name = ReadCString(data, strtab.Offset + (long)value, (ulong)(strtab.Size - (long)value));
            if (!string.IsNullOrWhiteSpace(name)) result.Add(name);
        }
        return result;
    }

    private static ElfSection ReadSection(byte[] data, int offset, bool is64, bool bigEndian)
    {
        var nameIndex = ReadUInt32(data, offset, bigEndian);
        var type = ReadUInt32(data, offset + 4, bigEndian);
        if (is64) return new ElfSection(nameIndex, type, (long)ReadUInt64(data, offset + 24, bigEndian), (long)ReadUInt64(data, offset + 32, bigEndian));
        return new ElfSection(nameIndex, type, ReadUInt32(data, offset + 16, bigEndian), ReadUInt32(data, offset + 20, bigEndian));
    }

    private static string ResolveName(byte[] data, ElfSection? strtab, uint nameIndex)
    {
        if (strtab is null || strtab.Offset <= 0 || strtab.Offset >= data.Length || nameIndex >= (ulong)strtab.Size) return $"<sección {nameIndex}>";
        var name = ReadCString(data, strtab.Offset + nameIndex, (ulong)strtab.Size - nameIndex);
        return string.IsNullOrWhiteSpace(name) ? "<sin nombre>" : name;
    }

    private static string ReadCString(byte[] data, long offset, ulong maxLength)
    {
        if (offset < 0 || offset >= data.Length || maxLength == 0) return string.Empty;
        var limit = (int)Math.Min((ulong)(data.Length - offset), Math.Min(maxLength, 512));
        var length = 0;
        while (length < limit && data[offset + length] != 0) length++;
        return length == 0 ? string.Empty : Encoding.ASCII.GetString(data, (int)offset, length);
    }

    private static bool IsSuspiciousSectionName(string name) =>
        name.Equals(".packed", StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith("UPX", StringComparison.OrdinalIgnoreCase) ||
        name.Equals(".aspack", StringComparison.OrdinalIgnoreCase) ||
        name.Equals(".themida", StringComparison.OrdinalIgnoreCase) ||
        name.Equals(".vmp0", StringComparison.OrdinalIgnoreCase) ||
        name.Equals(".nsp0", StringComparison.OrdinalIgnoreCase);

    private static async Task<byte[]> ReadBounded(string path, CancellationToken token)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, true);
        var length = (int)Math.Min(stream.Length, MaxInspectionBytes);
        var data = new byte[length];
        var offset = 0;
        while (offset < length) { var read = await stream.ReadAsync(data.AsMemory(offset), token); if (read == 0) break; offset += read; }
        return offset == length ? data : data[..offset];
    }

    private static double? SectionEntropy(byte[] data, long pointer, long size)
    {
        if (size <= 0 || pointer < 0 || pointer >= data.Length) return null;
        var length = (int)Math.Min(size, data.Length - pointer);
        Span<int> counts = stackalloc int[256];
        foreach (var value in data.AsSpan((int)pointer, length)) counts[value]++;
        double entropy = 0;
        foreach (var count in counts) if (count > 0) { var p = (double)count / length; entropy -= p * Math.Log2(p); }
        return entropy;
    }

    private static string TypeName(ushort value) => value switch { 0 => "ET_NONE", 1 => "ET_REL (objeto relocatable)", 2 => "ET_EXEC (ejecutable)", 3 => "ET_DYN (compartido/PIE)", 4 => "ET_CORE (volcado de memoria)", _ => $"Desconocido (0x{value:X4})" };
    private static string MachineName(ushort value) => value switch { 0x03 => "x86", 0x3e => "x86-64", 0x28 => "ARM", 0xb7 => "ARM64", 0x08 => "MIPS", 0x16 => "S/390", 0x15 => "PowerPC", 0x2a => "SuperH", 0x02 => "SPARC", 0x32 => "IA-64", 0xf3 => "RISC-V", _ => $"Desconocida (0x{value:X4})" };
    private static string SectionTypeName(uint value) => value switch { 0 => "SHT_NULL", 1 => "SHT_PROGBITS", 2 => "SHT_SYMTAB", 3 => "SHT_STRTAB", 4 => "SHT_RELA", 5 => "SHT_HASH", 6 => "SHT_DYNAMIC", 7 => "SHT_NOTE", 8 => "SHT_NOBITS", 9 => "SHT_REL", 11 => "SHT_DYNSYM", _ => $"0x{value:X8}" };

    private static ushort ReadUInt16(byte[] data, int offset, bool bigEndian) => bigEndian ? BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(offset, 2)) : BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(offset, 2));
    private static uint ReadUInt32(byte[] data, int offset, bool bigEndian) => bigEndian ? BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(offset, 4)) : BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset, 4));
    private static ulong ReadUInt64(byte[] data, int offset, bool bigEndian) => bigEndian ? BinaryPrimitives.ReadUInt64BigEndian(data.AsSpan(offset, 8)) : BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(offset, 8));
    private static int ReadInt32(byte[] data, int offset, bool bigEndian) => bigEndian ? BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(offset, 4)) : BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(offset, 4));
    private static void Add(AnalyzerOutput output, AnalyzerContext context, ArtifactKind kind, string name, string value, string detail, ConfidenceLevel confidence = ConfidenceLevel.Observed) => output.Artifacts.Add(new AnalysisArtifact { EvidenceId = context.Evidence.Id, AnalysisRunId = context.AnalysisRunId, Kind = kind, Name = name, Value = value, Context = detail, Confidence = confidence });
    private sealed record ElfSection(uint NameIndex, uint Type, long Offset, long Size) { public string ResolvedName { get; init; } = string.Empty; }
}

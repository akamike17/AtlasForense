using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using AtlasForense.Models;

namespace AtlasForense.Forensics;

public sealed class PortableExecutableAnalyzer : IForensicAnalyzer
{
    private const int MaxInspectionBytes = 64 * 1024 * 1024;
    private const int MaxSections = 96;
    public string Id => "windows-pe-structure";
    public string Version => "1.0.0";

    public bool CanAnalyze(EvidenceItem evidence) =>
        new[] { ".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".efi" }
            .Contains(Path.GetExtension(evidence.OriginalFileName), StringComparer.OrdinalIgnoreCase);

    public async Task<AnalyzerOutput> AnalyzeAsync(AnalyzerContext context)
    {
        var data = await ReadBounded(context.FilePath, context.CancellationToken);
        var fileLength = new FileInfo(context.FilePath).Length;
        var output = new AnalyzerOutput();
        if (data.Length < 64 || data[0] != (byte)'M' || data[1] != (byte)'Z')
            throw new InvalidDataException("La extensión indica un ejecutable Windows, pero falta la firma DOS MZ.");

        var peOffset = ReadInt32(data, 0x3c);
        if (peOffset < 64 || peOffset > data.Length - 24 || !data.AsSpan(peOffset, 4).SequenceEqual("PE\0\0"u8))
            throw new InvalidDataException("La cabecera PE es inválida o queda fuera del límite de inspección.");

        var coff = peOffset + 4;
        var machine = ReadUInt16(data, coff);
        var sectionCount = ReadUInt16(data, coff + 2);
        var timestamp = ReadUInt32(data, coff + 4);
        var optionalSize = ReadUInt16(data, coff + 16);
        var characteristics = ReadUInt16(data, coff + 18);
        var optional = coff + 20;
        if (sectionCount == 0 || sectionCount > MaxSections || optionalSize < 70 || optional > data.Length - optionalSize)
            throw new InvalidDataException("La tabla de secciones o la cabecera opcional PE no es válida.");

        var magic = ReadUInt16(data, optional);
        if (magic is not (0x10b or 0x20b)) throw new InvalidDataException("El formato de cabecera opcional PE no está soportado.");
        var is64 = magic == 0x20b;
        var entryPoint = ReadUInt32(data, optional + 16);
        var imageBase = is64 ? ReadUInt64(data, optional + 24) : ReadUInt32(data, optional + 28);
        var subsystem = ReadUInt16(data, optional + 68);

        Add(output, context, ArtifactKind.Metadata, "Arquitectura PE", MachineName(machine), $"machine=0x{machine:X4}; formato={(is64 ? "PE32+" : "PE32")}");
        Add(output, context, ArtifactKind.Metadata, "Punto de entrada", $"0x{entryPoint:X8}", $"RVA; imageBase=0x{imageBase:X}");
        Add(output, context, ArtifactKind.Metadata, "Subsistema", SubsystemName(subsystem), $"subsystem={subsystem}");
        Add(output, context, ArtifactKind.Metadata, "Características COFF", $"0x{characteristics:X4}", DescribeCharacteristics(characteristics));

        if (TryConvertTimestamp(timestamp, out var compiledAt))
        {
            Add(output, context, ArtifactKind.Metadata, "Timestamp COFF", compiledAt.ToString("O"), "Valor observado en cabecera; puede haber sido alterado por el productor.");
            output.Events.Add(new TimelineEvent { EvidenceId = context.Evidence.Id, OccurredAtUtc = compiledAt, Category = "PE", Title = "Timestamp de compilación declarado", Description = "Timestamp COFF observado; no confirma por sí mismo la fecha real de compilación.", Source = $"{context.Evidence.Identifier}/pe-header", Confidence = ConfidenceLevel.Inferred });
        }
        else Add(output, context, ArtifactKind.Capability, "Anomalía PE", "Timestamp COFF ausente o no plausible", $"raw={timestamp}", ConfidenceLevel.Inferred);

        var sectionTable = optional + optionalSize;
        if (sectionTable > data.Length - sectionCount * 40) throw new InvalidDataException("La tabla de secciones PE está truncada.");
        long lastRawEnd = 0;
        var executableWritable = 0;
        var highEntropy = 0;
        var sections = new List<PeSection>();
        for (var index = 0; index < sectionCount; index++)
        {
            var offset = sectionTable + index * 40;
            var name = ReadSectionName(data.AsSpan(offset, 8));
            var virtualSize = ReadUInt32(data, offset + 8);
            var virtualAddress = ReadUInt32(data, offset + 12);
            var rawSize = ReadUInt32(data, offset + 16);
            var rawPointer = ReadUInt32(data, offset + 20);
            var flags = ReadUInt32(data, offset + 36);
            sections.Add(new PeSection(name, virtualAddress, virtualSize, rawPointer, rawSize));
            lastRawEnd = Math.Max(lastRawEnd, (long)rawPointer + rawSize);
            var permissions = $"{((flags & 0x40000000) != 0 ? "R" : "-")}{((flags & 0x80000000) != 0 ? "W" : "-")}{((flags & 0x20000000) != 0 ? "X" : "-")}";
            var entropy = SectionEntropy(data, rawPointer, rawSize);
            var entropyText = entropy.HasValue ? entropy.Value.ToString("F4", CultureInfo.InvariantCulture) : "no muestreada";
            Add(output, context, ArtifactKind.Metadata, "Sección PE", name, $"RVA=0x{virtualAddress:X8}; virtual={virtualSize}; raw={rawSize}; permisos={permissions}; entropía={entropyText}");
            if ((flags & 0xA0000000) == 0xA0000000)
            {
                executableWritable++;
                Add(output, context, ArtifactKind.Capability, "Sección escribible y ejecutable", name, $"permisos={permissions}; revisar empaquetado o código automodificable", ConfidenceLevel.Inferred);
            }
            if (entropy is >= 7.2)
            {
                highEntropy++;
                Add(output, context, ArtifactKind.Entropy, "Alta entropía de sección", name, entropyText, ConfidenceLevel.Inferred);
            }
        }

        if (lastRawEnd > 0 && fileLength > lastRawEnd)
            Add(output, context, ArtifactKind.Metadata, "Overlay PE", (fileLength - lastRawEnd).ToString(CultureInfo.InvariantCulture), $"bytes posteriores al último bloque raw; offset={lastRawEnd}");

        var imports = ReadImports(data, optional, optionalSize, is64, sections, output, context);

        output.Summary = $"PE estático: {MachineName(machine)}, {(is64 ? "64" : "32")} bits, {sectionCount} secciones, {imports.Modules} módulo(s), {imports.Functions} import(s), {executableWritable} WX, {highEntropy} con alta entropía; muestra no cargada ni ejecutada.";
        return output;
    }

    private static (int Modules, int Functions) ReadImports(byte[] data, int optional, int optionalSize, bool is64, IReadOnlyList<PeSection> sections, AnalyzerOutput output, AnalyzerContext context)
    {
        var directory = (is64 ? 112 : 96) + 8;
        if (optionalSize < directory + 8) return (0, 0);
        var importRva = ReadUInt32(data, optional + directory);
        var importSize = ReadUInt32(data, optional + directory + 4);
        if (importRva == 0 || importSize == 0 || !TryMapRva(importRva, sections, data.Length, out var descriptorOffset)) return (0, 0);
        var modules = 0;
        var functions = 0;
        var capabilityApis = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var descriptorLimit = (int)Math.Min(256u, Math.Max(1u, importSize / 20));
        for (var descriptor = 0; descriptor < descriptorLimit && descriptorOffset <= data.Length - 20; descriptor++, descriptorOffset += 20)
        {
            var originalThunk = ReadUInt32(data, descriptorOffset);
            var nameRva = ReadUInt32(data, descriptorOffset + 12);
            var firstThunk = ReadUInt32(data, descriptorOffset + 16);
            if (originalThunk == 0 && nameRva == 0 && firstThunk == 0) break;
            if (!TryMapRva(nameRva, sections, data.Length, out var nameOffset)) continue;
            var module = ReadAsciiZ(data, nameOffset, 260);
            if (string.IsNullOrWhiteSpace(module)) continue;
            modules++;
            Add(output, context, ArtifactKind.Metadata, "Módulo importado", module, $"descriptor={descriptor}; RVA=0x{nameRva:X8}");
            if (!output.Entities.Any(x => x.Type == "Module" && x.Value.Equals(module, StringComparison.OrdinalIgnoreCase)))
                output.Entities.Add(new CaseEntity { Type = "Module", Value = module.ToLowerInvariant(), DisplayName = module, Confidence = ConfidenceLevel.Observed, EvidenceIds = [context.Evidence.Id] });
            var thunkRva = originalThunk != 0 ? originalThunk : firstThunk;
            if (!TryMapRva(thunkRva, sections, data.Length, out var thunkOffset)) continue;
            var width = is64 ? 8 : 4;
            for (var index = 0; index < 10_000 && functions < 20_000 && thunkOffset <= data.Length - width; index++, thunkOffset += width)
            {
                var value = is64 ? ReadUInt64(data, thunkOffset) : ReadUInt32(data, thunkOffset);
                if (value == 0) break;
                var ordinalFlag = is64 ? 0x8000000000000000UL : 0x80000000UL;
                string function;
                if ((value & ordinalFlag) != 0) function = $"ordinal:{value & 0xffff}";
                else if (value <= uint.MaxValue && TryMapRva((uint)value, sections, data.Length, out var importNameOffset) && importNameOffset <= data.Length - 3)
                    function = ReadAsciiZ(data, importNameOffset + 2, 512);
                else continue;
                if (string.IsNullOrWhiteSpace(function)) continue;
                functions++;
                Add(output, context, ArtifactKind.Capability, "API importada", $"{module}!{function}", $"thunk={index}; {(originalThunk != 0 ? "INT" : "IAT")}");
                capabilityApis.Add(function);
            }
        }
        AddImportCapabilities(output, context, capabilityApis);
        return (modules, functions);
    }

    private static void AddImportCapabilities(AnalyzerOutput output, AnalyzerContext context, HashSet<string> apis)
    {
        var capabilities = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            ["Ejecución de procesos"] = ["CreateProcessA", "CreateProcessW", "ShellExecuteA", "ShellExecuteW", "WinExec"],
            ["Memoria de otro proceso"] = ["OpenProcess", "WriteProcessMemory", "VirtualAllocEx", "CreateRemoteThread", "NtWriteVirtualMemory"],
            ["Persistencia en registro"] = ["RegSetValueA", "RegSetValueW", "RegCreateKeyA", "RegCreateKeyW"],
            ["Comunicación de red"] = ["connect", "InternetOpenA", "InternetOpenW", "HttpSendRequestA", "HttpSendRequestW", "WinHttpSendRequest"],
            ["Captura de entrada"] = ["SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState"]
        };
        foreach (var capability in capabilities)
        {
            var observed = capability.Value.Where(apis.Contains).ToArray();
            if (observed.Length > 0) Add(output, context, ArtifactKind.Capability, "Capacidad por imports", capability.Key, string.Join(", ", observed), ConfidenceLevel.Inferred);
        }
    }

    private static bool TryMapRva(uint rva, IReadOnlyList<PeSection> sections, int dataLength, out int offset)
    {
        foreach (var section in sections)
        {
            var span = Math.Max(section.VirtualSize, section.RawSize);
            if (rva < section.VirtualAddress || (ulong)rva >= (ulong)section.VirtualAddress + span) continue;
            var delta = rva - section.VirtualAddress;
            if (delta >= section.RawSize) continue;
            var mapped = (ulong)section.RawPointer + delta;
            if (mapped >= (ulong)dataLength) break;
            offset = (int)mapped;
            return true;
        }
        offset = 0;
        return false;
    }

    private static string ReadAsciiZ(byte[] data, int offset, int maxLength)
    {
        if (offset < 0 || offset >= data.Length) return string.Empty;
        var length = 0;
        while (length < maxLength && offset + length < data.Length && data[offset + length] != 0) length++;
        return length == 0 || length == maxLength ? string.Empty : Encoding.ASCII.GetString(data, offset, length);
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

    private static double? SectionEntropy(byte[] data, uint pointer, uint size)
    {
        if (size == 0 || pointer >= data.Length) return null;
        var length = (int)Math.Min(size, (uint)(data.Length - pointer));
        Span<int> counts = stackalloc int[256];
        foreach (var value in data.AsSpan((int)pointer, length)) counts[value]++;
        double entropy = 0;
        foreach (var count in counts) if (count > 0) { var p = (double)count / length; entropy -= p * Math.Log2(p); }
        return entropy;
    }

    private static bool TryConvertTimestamp(uint value, out DateTimeOffset timestamp)
    {
        timestamp = DateTimeOffset.FromUnixTimeSeconds(value);
        return value != 0 && timestamp.Year is >= 1993 and <= 2100;
    }

    private static string ReadSectionName(ReadOnlySpan<byte> value)
    {
        var end = value.IndexOf((byte)0); if (end < 0) end = value.Length;
        var name = Encoding.ASCII.GetString(value[..end]);
        return string.IsNullOrWhiteSpace(name) ? "<sin nombre>" : name;
    }

    private static string MachineName(ushort value) => value switch { 0x014c => "x86", 0x8664 => "x64", 0x01c0 or 0x01c4 => "ARM", 0xaa64 => "ARM64", 0x0200 => "Itanium", _ => $"Desconocida (0x{value:X4})" };
    private static string SubsystemName(ushort value) => value switch { 1 => "Native", 2 => "Windows GUI", 3 => "Windows Console", 9 => "Windows CE", 10 => "EFI Application", 11 => "EFI Boot Service", 12 => "EFI Runtime", 14 => "Xbox", 16 => "Windows Boot", _ => $"Desconocido ({value})" };
    private static string DescribeCharacteristics(ushort value) => $"ejecutable={((value & 0x0002) != 0)}; dll={((value & 0x2000) != 0)}; largeAddressAware={((value & 0x0020) != 0)}; relocacionesEliminadas={((value & 0x0001) != 0)}";
    private static ushort ReadUInt16(byte[] data, int offset) => BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(offset, 2));
    private static uint ReadUInt32(byte[] data, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset, 4));
    private static ulong ReadUInt64(byte[] data, int offset) => BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(offset, 8));
    private static int ReadInt32(byte[] data, int offset) => BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(offset, 4));
    private static void Add(AnalyzerOutput output, AnalyzerContext context, ArtifactKind kind, string name, string value, string detail, ConfidenceLevel confidence = ConfidenceLevel.Observed) => output.Artifacts.Add(new AnalysisArtifact { EvidenceId = context.Evidence.Id, AnalysisRunId = context.AnalysisRunId, Kind = kind, Name = name, Value = value, Context = detail, Confidence = confidence });
    private sealed record PeSection(string Name, uint VirtualAddress, uint VirtualSize, uint RawPointer, uint RawSize);
}

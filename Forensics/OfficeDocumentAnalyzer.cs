using System.Globalization;
using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using AtlasForense.Models;
using AtlasForense.Services;

namespace AtlasForense.Forensics;

public sealed partial class OfficeDocumentAnalyzer(IArchiveSafetyInspector safetyInspector) : IForensicAnalyzer
{
    private const long MaxMetadataBytes = 1_048_576;
    private const int MaxRelationshipFiles = 512;
    private const int MaxUrls = 100;
    private const int MaxOleEntries = 4_096;
    private const int MaxChainSteps = 1_000_000;
    private static readonly string[] OoxmlExtensions = [".docx", ".docm", ".dotx", ".dotm", ".xlsx", ".xlsm", ".xlsb", ".xlam", ".pptx", ".pptm", ".ppsm", ".ppam", ".potx", ".potm"];
    private static readonly string[] OleExtensions = [".doc", ".xls", ".ppt", ".dot", ".xlt", ".pot"];
    private static readonly byte[] OleMagic = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];

    public string Id => "office-document-structure";
    public string Version => "1.0.0";

    public bool CanAnalyze(EvidenceItem evidence)
    {
        var extension = Path.GetExtension(evidence.OriginalFileName);
        return OoxmlExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase) || OleExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase);
    }

    public async Task<AnalyzerOutput> AnalyzeAsync(AnalyzerContext context)
    {
        var header = new byte[8];
        await using (var stream = new FileStream(context.FilePath, FileMode.Open, FileAccess.Read, FileShare.Read, 8, true))
            await stream.ReadAsync(header.AsMemory(0, (int)Math.Min(8, stream.Length)), context.CancellationToken);

        if (header.AsSpan(0, 4).SequenceEqual(new byte[] { 0x50, 0x4b, 0x03, 0x04 })) return await AnalyzeOoxmlAsync(context);
        if (header.AsSpan(0, 8).SequenceEqual(OleMagic)) return AnalyzeOle(context, await ReadBounded(context.FilePath, context.CancellationToken));
        throw new InvalidDataException("La extensión indica un documento Office, pero la firma no es ZIP/OOXML ni OLE Compound File.");
    }

    private async Task<AnalyzerOutput> AnalyzeOoxmlAsync(AnalyzerContext context)
    {
        var safety = await safetyInspector.InspectZipAsync(context.FilePath, context.CancellationToken);
        if (!safety.Safe) throw new InvalidDataException($"El contenedor OOXML no superó la inspección de seguridad: {safety.Message}");

        var output = new AnalyzerOutput();
        using var stream = new FileStream(context.FilePath, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.SequentialScan);
        using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: false);
        var macroProject = false;
        var relationshipsScanned = 0;
        var urls = 0;
        var embedded = 0;

        foreach (var entry in archive.Entries)
        {
            context.CancellationToken.ThrowIfCancellationRequested();
            var name = entry.FullName;
            if (name.EndsWith("vbaProject.bin", StringComparison.OrdinalIgnoreCase))
            {
                macroProject = true;
                Add(output, context, ArtifactKind.Capability, "Proyecto VBA", name, "El contenedor incluye un proyecto de macros VBA; el código no se decompila en esta fase.", ConfidenceLevel.Observed);
            }
            else if (name.StartsWith("word/embeddings/", StringComparison.OrdinalIgnoreCase) || name.StartsWith("ppt/embeddings/", StringComparison.OrdinalIgnoreCase) || name.StartsWith("xl/embeddings/", StringComparison.OrdinalIgnoreCase))
            {
                embedded++;
                Add(output, context, ArtifactKind.Metadata, "Objeto embebido", name, $"tamaño={entry.Length}; puede ser un objeto OLE binario");
            }
            else if (name.Equals("[Content_Types].xml", StringComparison.OrdinalIgnoreCase))
            {
                var contentTypes = await ReadEntryTextAsync(entry, context.CancellationToken);
                var declared = OoxmlContentType(contentTypes);
                Add(output, context, ArtifactKind.FileType, "Tipo OOXML", declared, "Declarado en [Content_Types].xml");
                if (contentTypes.Contains("macroEnabled", StringComparison.OrdinalIgnoreCase))
                {
                    macroProject = true;
                    Add(output, context, ArtifactKind.Capability, "Formato habilitado para macros", declared, "El tipo de contenido declara capacidades de macro.", ConfidenceLevel.Inferred);
                }
            }
            else if (name.Equals("docProps/core.xml", StringComparison.OrdinalIgnoreCase))
            {
                foreach (var (label, value) in ReadCoreProperties(await ReadEntryTextAsync(entry, context.CancellationToken)))
                {
                    Add(output, context, ArtifactKind.Metadata, $"Metadato {label}", value, "docProps/core.xml");
                    if (label is "Creado" or "Modificado" && DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var when))
                        output.Events.Add(new TimelineEvent { EvidenceId = context.Evidence.Id, OccurredAtUtc = when, Category = "Documento Office", Title = $"{label} declarado en metadatos", Description = $"{label}={value}; declarado por el productor, no verificado.", Source = $"{context.Evidence.Identifier}/docProps/core.xml", Confidence = ConfidenceLevel.Inferred });
                    if (label is "Creador" or "Última modificación por" && !output.Entities.Any(x => x.Type == "Person" && x.Value.Equals(value, StringComparison.OrdinalIgnoreCase)))
                        output.Entities.Add(new CaseEntity { Type = "Person", Value = value.ToLowerInvariant(), DisplayName = value, Confidence = ConfidenceLevel.Observed, EvidenceIds = [context.Evidence.Id] });
                }
            }
            else if (name.Equals("docProps/app.xml", StringComparison.OrdinalIgnoreCase))
            {
                foreach (var (label, value) in ReadAppProperties(await ReadEntryTextAsync(entry, context.CancellationToken)))
                    Add(output, context, ArtifactKind.Metadata, $"Metadato {label}", value, "docProps/app.xml");
            }
            else if (relationshipsScanned < MaxRelationshipFiles && name.Contains("_rels", StringComparison.OrdinalIgnoreCase) && name.EndsWith(".rels", StringComparison.OrdinalIgnoreCase))
            {
                relationshipsScanned++;
                foreach (var target in ReadExternalTargets(await ReadEntryTextAsync(entry, context.CancellationToken)))
                {
                    if (urls >= MaxUrls) break;
                    urls++;
                    Add(output, context, ArtifactKind.Url, "Relación externa", target, $"{name}; destino externo declarado en relaciones OOXML");
                    if (!output.Indicators.Any(x => x.Type == IndicatorType.Url && x.Value.Equals(target, StringComparison.OrdinalIgnoreCase)))
                        output.Indicators.Add(new CaseIndicator { Type = Uri.IsWellFormedUriString(target, UriKind.Absolute) ? IndicatorType.Url : IndicatorType.Other, Value = target, NormalizedValue = target.ToLowerInvariant(), Description = $"Relación externa en {name}", Confidence = ConfidenceLevel.Observed, EvidenceIds = [context.Evidence.Id] });
                }
            }
        }

        output.Summary = $"Office OOXML: {safety.EntryCount} entrada(s), macros={(macroProject ? "proyecto VBA presente" : "sin proyecto VBA detectado")}, {embedded} objeto(s) embebido(s), {urls} relación(es) externa(s); contenido no ejecutado.";
        return output;
    }

    private AnalyzerOutput AnalyzeOle(AnalyzerContext context, byte[] data)
    {
        var output = new AnalyzerOutput();
        if (data.Length < 512) throw new InvalidDataException("El contenedor OLE está truncado antes de completar su cabecera.");
        var major = ReadUInt16(data, 26);
        var byteOrder = ReadUInt16(data, 28);
        if (byteOrder != 0xfffe) throw new InvalidDataException("El orden de bytes del contenedor OLE no es little-endian como exige la especificación.");
        var sectorShift = ReadUInt16(data, 30);
        var miniSectorShift = ReadUInt16(data, 32);
        if (sectorShift is < 7 or > 16 || miniSectorShift is < 2 or > 12) throw new InvalidDataException("El tamaño de sector OLE declarado no es válido.");
        var sectorSize = 1 << sectorShift;
        var directorySectorsDeclared = ReadUInt32(data, 40);
        if (major == 3 && directorySectorsDeclared != 0) throw new InvalidDataException("El contenedor OLE v3 declara un número de sectores de directorio distinto de cero.");
        var firstDirectorySector = (int)ReadUInt32(data, 48);
        var firstDifatSector = (int)ReadUInt32(data, 68);
        var difatCount = (int)ReadUInt32(data, 72);

        var fat = BuildFat(data, sectorSize, firstDifatSector, difatCount);
        var entries = ReadDirectoryEntries(data, sectorSize, fat, firstDirectorySector);
        if (entries.Count == 0) throw new InvalidDataException("El directorio del contenedor OLE no contiene entradas legibles.");

        Add(output, context, ArtifactKind.Metadata, "Versión CFB", $"v{major}", $"sector={sectorSize}; minisector={1 << miniSectorShift}; entradas={entries.Count}");
        var root = entries.FirstOrDefault(x => x.Type == 5);
        if (root is not null && !root.Clsid.Equals(Guid.Empty))
        {
            var product = KnownClsid(root.Clsid);
            Add(output, context, ArtifactKind.Metadata, "CLSID raíz", root.Clsid.ToString("D").ToUpperInvariant(), product);
        }

        var macroSignals = 0;
        foreach (var entry in entries.Take(MaxOleEntries))
        {
            var kind = entry.Type switch { 1 => "Storage", 2 => "Stream", 5 => "Root", _ => "Entrada" };
            Add(output, context, ArtifactKind.Metadata, kind, entry.Name, $"sector={entry.FirstSector}; tamaño={entry.Size}");
            if (kind != "Entrada" && IsMacroRelated(entry.Name))
            {
                macroSignals++;
                Add(output, context, ArtifactKind.Capability, "Posibles macros VBA", entry.Name, "Nombre de almacenamiento o flujo asociado habitualmente a proyectos de macros; el código no se decompila en esta fase.", ConfidenceLevel.Inferred);
            }
            if (entry.Name.Equals("\u0001CompObj", StringComparison.Ordinal))
                Add(output, context, ArtifactKind.Metadata, "Objeto OLE embebido", entry.Name, "Flujo CompObj; indica un objeto OLE incrustado.", ConfidenceLevel.Observed);
            if (entry.Name is "WordDocument" or "Workbook" or "Book" or "PowerPoint Document")
                Add(output, context, ArtifactKind.FileType, "Formato binario Office", entry.Name, "Flujo principal del formato binario detectado por nombre.");
        }
        if (macroSignals > 0)
            output.Indicators.Add(new CaseIndicator { Type = IndicatorType.Other, Value = "macro-vba-ole", NormalizedValue = "macro-vba-ole", Description = $"{macroSignals} estructura(s) con nombres asociados a macros VBA", Confidence = ConfidenceLevel.Inferred, EvidenceIds = [context.Evidence.Id] });

        output.Summary = $"Office OLE/CFB: {entries.Count} entrada(s) de directorio, {(macroSignals > 0 ? $"{macroSignals} indicio(s) de macros" : "sin indicios de macros por nombre")}; contenido no ejecutado.";
        return output;
    }

    private static List<uint> BuildFat(byte[] data, int sectorSize, int firstDifatSector, int difatCount)
    {
        var difat = new List<int>();
        for (var index = 0; index < 109; index++)
        {
            var sector = (int)ReadUInt32(data, 76 + index * 4);
            if (sector >= 0) difat.Add(sector);
        }
        var next = firstDifatSector;
        var entriesPerSector = sectorSize / 4;
        for (var chain = 0; chain < difatCount && chain < MaxChainSteps && next >= 0; chain++)
        {
            var offset = SectorOffset(next, sectorSize);
            if (offset < 0 || offset > data.Length - sectorSize) break;
            for (var index = 0; index < entriesPerSector - 1; index++)
            {
                var sector = (int)ReadUInt32(data, offset + index * 4);
                if (sector >= 0) difat.Add(sector);
            }
            next = (int)ReadUInt32(data, offset + sectorSize - 4);
        }

        var fat = new List<uint>();
        foreach (var sector in difat)
        {
            var offset = SectorOffset(sector, sectorSize);
            if (offset < 0 || offset > data.Length - sectorSize) continue;
            for (var index = 0; index < entriesPerSector; index++) fat.Add(ReadUInt32(data, offset + index * 4));
        }
        return fat;
    }

    private static List<OleEntry> ReadDirectoryEntries(byte[] data, int sectorSize, List<uint> fat, int firstDirectorySector)
    {
        var entries = new List<OleEntry>();
        var sector = firstDirectorySector;
        var steps = 0;
        var entriesPerSector = sectorSize / 128;
        while (sector is >= 0 && sector < fat.Count && steps++ < MaxChainSteps)
        {
            var offset = SectorOffset(sector, sectorSize);
            if (offset < 0 || offset > data.Length - sectorSize) break;
            for (var index = 0; index < entriesPerSector; index++)
            {
                var entryOffset = offset + index * 128;
                var type = data[entryOffset + 66];
                if (type is not (1 or 2 or 5)) continue;
                var nameLength = ReadUInt16(data, entryOffset + 64);
                if (nameLength < 2 || nameLength > 64) continue;
                var name = Encoding.Unicode.GetString(data, entryOffset, nameLength - 2).TrimEnd('\0');
                if (string.IsNullOrWhiteSpace(name)) continue;
                var firstSector = (int)ReadUInt32(data, entryOffset + 116);
                var size = (long)ReadUInt32(data, entryOffset + 120);
                var clsid = type == 5 ? new Guid(data.AsSpan(entryOffset + 80, 16)) : Guid.Empty;
                entries.Add(new OleEntry(name, type, firstSector, size, clsid));
            }
            var next = fat[sector];
            if (next >= 0xfffffffa) break;
            sector = (int)next;
        }
        return entries;
    }

    private static int SectorOffset(int sector, int sectorSize)
    {
        if (sector < 0 || sector > (int.MaxValue - 512) / sectorSize) return -1;
        return 512 + sector * sectorSize;
    }

    private static bool IsMacroRelated(string name) =>
        name.Equals("Macros", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("PROJECT", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("PROJECTwm", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("PROJECTlc", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("_VBA_PROJECT", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("VBA", StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith("_VBA_PROJECT", StringComparison.OrdinalIgnoreCase);

    private static string OoxmlContentType(string contentTypes)
    {
        foreach (Match match in ContentTypeRegex().Matches(contentTypes))
        {
            var contentType = match.Groups[1].Value;
            if (contentType.Contains("ms-word", StringComparison.OrdinalIgnoreCase)) return "Word habilitado para macros (DOCM)";
            if (contentType.Contains("ms-excel", StringComparison.OrdinalIgnoreCase)) return "Excel habilitado para macros (XLSM)";
            if (contentType.Contains("ms-powerpoint", StringComparison.OrdinalIgnoreCase)) return "PowerPoint habilitado para macros (PPTM)";
            if (contentType.Contains("wordprocessingml", StringComparison.OrdinalIgnoreCase)) return contentType.Contains("macroEnabled", StringComparison.OrdinalIgnoreCase) ? "Word habilitado para macros (DOCM)" : "Documento Word (DOCX)";
            if (contentType.Contains("spreadsheetml", StringComparison.OrdinalIgnoreCase)) return contentType.Contains("macroEnabled", StringComparison.OrdinalIgnoreCase) ? "Excel habilitado para macros (XLSM)" : "Libro Excel (XLSX)";
            if (contentType.Contains("presentationml", StringComparison.OrdinalIgnoreCase)) return contentType.Contains("macroEnabled", StringComparison.OrdinalIgnoreCase) ? "PowerPoint habilitado para macros (PPTM)" : "Presentación PowerPoint (PPTX)";
        }
        return "OOXML sin tipo principal reconocido";
    }

    private static IEnumerable<(string Label, string Value)> ReadCoreProperties(string xml)
    {
        var values = new List<(string, string)>();
        TryExtract(xml, "creator", "Creador", values);
        TryExtract(xml, "lastModifiedBy", "Última modificación por", values);
        TryExtract(xml, "created", "Creado", values);
        TryExtract(xml, "modified", "Modificado", values);
        TryExtract(xml, "title", "Título", values);
        TryExtract(xml, "subject", "Asunto", values);
        return values;
    }

    private static IEnumerable<(string Label, string Value)> ReadAppProperties(string xml)
    {
        var values = new List<(string, string)>();
        TryExtract(xml, "Application", "Aplicación", values);
        TryExtract(xml, "AppVersion", "Versión", values);
        TryExtract(xml, "Company", "Organización", values);
        return values;
    }

    private static void TryExtract(string xml, string element, string label, List<(string, string)> values)
    {
        var match = Regex.Match(xml, $"<(?:[a-zA-Z0-9]+:)?{Regex.Escape(element)}[^>]*>([^<]*)</(?:[a-zA-Z0-9]+:)?{Regex.Escape(element)}>", RegexOptions.CultureInvariant);
        if (match.Success && !string.IsNullOrWhiteSpace(match.Groups[1].Value))
            values.Add((label, match.Groups[1].Value.Trim()));
    }

    private static IEnumerable<string> ReadExternalTargets(string relationshipsXml)
    {
        var targets = new List<string>();
        try
        {
            using var reader = XmlReader.Create(new StringReader(relationshipsXml), new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = MaxMetadataBytes * 2 });
            while (reader.Read())
            {
                if (reader.NodeType != XmlNodeType.Element || !reader.LocalName.Equals("Relationship", StringComparison.Ordinal)) continue;
                var mode = reader.GetAttribute("TargetMode");
                var target = reader.GetAttribute("Target");
                if (string.Equals(mode, "External", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(target)) targets.Add(target);
            }
        }
        catch (XmlException) { }
        return targets;
    }

    private static async Task<string> ReadEntryTextAsync(ZipArchiveEntry entry, CancellationToken token)
    {
        if (entry.Length > MaxMetadataBytes) return string.Empty;
        await using var content = entry.Open();
        using var reader = new StreamReader(content, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, bufferSize: 8192, leaveOpen: true);
        var buffer = new char[MaxMetadataBytes];
        var read = await reader.ReadAsync(buffer.AsMemory(), token);
        return new string(buffer, 0, read);
    }

    private static string KnownClsid(Guid clsid) => clsid.ToString("D").ToUpperInvariant() switch
    {
        "00020906-0000-0000-C000-000000000046" => "Word Document (Word 97-2003)",
        "00020820-0000-0000-C000-000000000046" => "Excel Worksheet (Excel 97-2003)",
        "00020830-0000-0000-C000-000000000046" => "Excel Chart (Excel 97-2003)",
        "64818D10-4F9B-11CF-86EA-00AA00B929E8" => "PowerPoint Presentation (97-2003)",
        "64818D11-4F9B-11CF-86EA-00AA00B929E8" => "PowerPoint Slide (97-2003)",
        _ => "CLSID no catalogado"
    };

    private static async Task<byte[]> ReadBounded(string path, CancellationToken token)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, true);
        var length = (int)Math.Min(stream.Length, 64 * 1024 * 1024);
        var data = new byte[length];
        var offset = 0;
        while (offset < length) { var read = await stream.ReadAsync(data.AsMemory(offset), token); if (read == 0) break; offset += read; }
        return offset == length ? data : data[..offset];
    }

    private static ushort ReadUInt16(byte[] data, int offset) => System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(offset, 2));
    private static uint ReadUInt32(byte[] data, int offset) => System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset, 4));
    private static void Add(AnalyzerOutput output, AnalyzerContext context, ArtifactKind kind, string name, string value, string detail, ConfidenceLevel confidence = ConfidenceLevel.Observed) => output.Artifacts.Add(new AnalysisArtifact { EvidenceId = context.Evidence.Id, AnalysisRunId = context.AnalysisRunId, Kind = kind, Name = name, Value = value, Context = detail, Confidence = confidence });

    [GeneratedRegex(@"ContentType=""([^""]*main[^""]*)""", RegexOptions.CultureInvariant)]
    private static partial Regex ContentTypeRegex();

    private sealed record OleEntry(string Name, byte Type, int FirstSector, long Size, Guid Clsid);
}

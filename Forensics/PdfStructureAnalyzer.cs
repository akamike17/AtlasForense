using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using AtlasForense.Models;

namespace AtlasForense.Forensics;

public sealed partial class PdfStructureAnalyzer : IForensicAnalyzer
{
    private const int MaxInspectionBytes = 64 * 1024 * 1024;
    private const int MaxKeywordHits = 25;
    private static readonly (string Keyword, string Name, string Detail)[] RiskKeywords =
    [
        ("/JavaScript", "JavaScript en PDF", "Presencia de JavaScript; los flujos pueden estar comprimidos y no ser visibles aquí."),
        ("/JS", "Acción JS", "Acción /JS observada; puede ejecutar JavaScript al abrirse el documento."),
        ("/OpenAction", "Acción automática de apertura", "/OpenAction ejecuta una acción al abrir el documento."),
        ("/AA", "Acciones adicionales", "/AA define acciones automáticas adicionales."),
        ("/Launch", "Lanzador externo", "/Launch puede invocar aplicaciones o archivos externos."),
        ("/GoToR", "Navegación remota", "/GoToR puede apuntar a recursos fuera del documento."),
        ("/GoToE", "Navegación embebida", "/GoToE puede apuntar a archivos embebidos."),
        ("/EmbeddedFile", "Archivo embebido", "El documento contiene archivos embebidos."),
        ("/XFA", "Formulario XFA", "Los formularios XFA pueden contener lógica scriptable."),
        ("/AcroForm", "Formulario AcroForm", "Presencia de formulario interactivo."),
        ("/Encrypt", "Cifrado de documento", "El diccionario /Encrypt indica cifrado o protección con contraseña."),
        ("/ObjStm", "Objetos en flujo comprimido", "/ObjStm oculta objetos dentro de flujos comprimidos.")
    ];

    public string Id => "pdf-structure";
    public string Version => "1.0.0";

    public bool CanAnalyze(EvidenceItem evidence) =>
        Path.GetExtension(evidence.OriginalFileName).Equals(".pdf", StringComparison.OrdinalIgnoreCase) ||
        evidence.DetectedFileType.Equals("PDF", StringComparison.OrdinalIgnoreCase);

    public async Task<AnalyzerOutput> AnalyzeAsync(AnalyzerContext context)
    {
        var data = await ReadBounded(context.FilePath, context.CancellationToken);
        var output = new AnalyzerOutput();
        if (data.Length < 8 || !data.AsSpan(0, 5).SequenceEqual("%PDF-"u8))
            throw new InvalidDataException("La evidencia no contiene la cabecera %PDF esperada.");

        var version = ReadAsciiLine(data, 5, 8);
        Add(output, context, ArtifactKind.Metadata, "Versión PDF", version, "Declarada en la cabecera; puede diferir de la versión mínima requerida por el catálogo.");

        var text = Encoding.Latin1.GetString(data);
        var objects = ObjectCount().Matches(text).Count;
        var eofCount = EofMarker().Matches(text).Count;
        var hasXref = text.Contains("xref", StringComparison.Ordinal);
        var startxref = text.Contains("startxref", StringComparison.Ordinal);
        Add(output, context, ArtifactKind.Metadata, "Objetos indirectos", objects.ToString(CultureInfo.InvariantCulture), "Conteo aproximado de marcadores 'obj'; los objetos en /ObjStm no se contabilizan individualmente.");
        Add(output, context, ArtifactKind.Metadata, "Tabla de referencias cruzadas", hasXref ? "xref clásico presente" : startxref ? "solo startxref (posible xref de flujo)" : "no localizada", "Inspección estática sin reconstrucción completa de la tabla.");
        if (eofCount > 1) Add(output, context, ArtifactKind.Metadata, "Actualizaciones incrementales", (eofCount - 1).ToString(CultureInfo.InvariantCulture), $"{eofCount} marcadores %%EOF observados; cada actualización incremental puede añadir u ocultar contenido.", ConfidenceLevel.Inferred);

        var riskCount = 0;
        foreach (var (keyword, name, detail) in RiskKeywords)
        {
            var offset = text.IndexOf(keyword, StringComparison.Ordinal);
            if (offset < 0) continue;
            riskCount++;
            Add(output, context, ArtifactKind.Capability, name, keyword, $"{detail}; primera aparición en offset={offset}", ConfidenceLevel.Inferred);
            if (keyword == "/Launch" || keyword == "/JavaScript" || keyword == "/EmbeddedFile")
                output.Indicators.Add(new CaseIndicator { Type = IndicatorType.Other, Value = keyword, NormalizedValue = keyword.ToLowerInvariant(), Description = $"Capacidad de riesgo observada en PDF en offset {offset}", Confidence = ConfidenceLevel.Observed, EvidenceIds = [context.Evidence.Id] });
        }

        var urls = 0;
        foreach (Match match in UrlRegex().Matches(text))
        {
            if (urls >= MaxKeywordHits) break;
            var value = match.Value.TrimEnd('.', ',', ';', ')', ']', '}', '\'', '"');
            urls++;
            Add(output, context, ArtifactKind.Url, "URL en PDF", value, $"Cadena URL observada en offset={match.Index}; puede estar dentro de un flujo comprimido decodificado parcialmente.", ConfidenceLevel.Observed);
            if (!output.Indicators.Any(x => x.Type == IndicatorType.Url && x.Value.Equals(value, StringComparison.OrdinalIgnoreCase)))
                output.Indicators.Add(new CaseIndicator { Type = IndicatorType.Url, Value = value, NormalizedValue = value.ToLowerInvariant(), Description = "Extraída del cuerpo del PDF", Confidence = ConfidenceLevel.Observed, EvidenceIds = [context.Evidence.Id] });
        }

        var flate = CountOccurrences(text, "/FlateDecode");
        if (flate > 0) Add(output, context, ArtifactKind.Metadata, "Flujos comprimidos", flate.ToString(CultureInfo.InvariantCulture), "Filtros /FlateDecode observados; el contenido comprimido no se decodifica en esta fase.");

        output.Summary = $"PDF estático: versión {version}, ~{objects} objeto(s), {eofCount} %%EOF, {riskCount} capacidad(es) de riesgo, {urls} URL(s); contenido comprimido no decodificado; muestra no ejecutada y red no utilizada.";
        return output;
    }

    private static int CountOccurrences(string text, string value)
    {
        var count = 0; var index = 0;
        while ((index = text.IndexOf(value, index, StringComparison.Ordinal)) >= 0) { count++; index += value.Length; }
        return count;
    }

    private static string ReadAsciiLine(byte[] data, int offset, int maxLength)
    {
        var length = 0;
        while (length < maxLength && offset + length < data.Length && data[offset + length] is >= (byte)'!' and <= (byte)'~') length++;
        return length == 0 ? "desconocida" : Encoding.ASCII.GetString(data, offset, length);
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

    private static void Add(AnalyzerOutput output, AnalyzerContext context, ArtifactKind kind, string name, string value, string detail, ConfidenceLevel confidence = ConfidenceLevel.Observed) => output.Artifacts.Add(new AnalysisArtifact { EvidenceId = context.Evidence.Id, AnalysisRunId = context.AnalysisRunId, Kind = kind, Name = name, Value = value, Context = detail, Confidence = confidence });

    [GeneratedRegex(@"\d+\s+\d+\s+obj\b", RegexOptions.CultureInvariant)] private static partial Regex ObjectCount();
    [GeneratedRegex(@"%%EOF", RegexOptions.CultureInvariant)] private static partial Regex EofMarker();
    [GeneratedRegex(@"https?://[^\s<>""'\)\]]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)] private static partial Regex UrlRegex();
}

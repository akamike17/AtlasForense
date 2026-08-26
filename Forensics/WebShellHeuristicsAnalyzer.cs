using System.Text;
using System.Text.RegularExpressions;
using AtlasForense.Models;

namespace AtlasForense.Forensics;

public sealed partial class WebShellHeuristicsAnalyzer : IForensicAnalyzer
{
    private const int MaxCharacters = 4_000_000;
    private const int MaxHits = 100;
    private static readonly string[] Extensions = [".php", ".phtml", ".php5", ".asp", ".aspx", ".ashx", ".asmx", ".cer", ".jsp", ".jspx", ".cfm", ".cgi", ".pl", ".war"];
    private static readonly (string Family, string Description, string[] Patterns)[] Signatures =
    [
        ("Shell PHP por petición", "Evalución o ejecución directa de datos enviados por el cliente", ["eval($_POST", "eval($_GET", "eval($_REQUEST", "@eval($_", "assert($_POST", "assert($_GET", "system($_", "exec($_", "shell_exec($_", "passthru($_", "popen($_"]),
        ("Ofuscación PHP", "Capas de decodificación habituales en shells PHP ofuscados", ["base64_decode(", "gzinflate(", "gzuncompress(", "gzdecode(", "str_rot13(", "create_function(", "preg_replace(\"/e", "preg_replace('/e", "call_user_func("]),
        ("Ejecución de comandos", "Primitivas de ejecución de procesos en el servidor", ["system(", "shell_exec(", "passthru(", "proc_open(", "cmd.exe", "/bin/sh", "/bin/bash", "powershell -", "whoami"]),
        ("Shell ASP/ASP.NET", "Patrones clásicos de web shell en IIS", ["Execute(Request", "ExecuteGlobal(", "eval(Request", "CreateObject(\"WSCRIPT.SHELL\"", "CreateObject(\"wscript.shell\"", "Process.Start", "WScript.Shell"]),
        ("Shell JSP", "Ejecución de comandos desde parámetros de petición en Java", ["Runtime.getRuntime().exec(request.getParameter", "ProcessBuilder(request", "getRuntime().exec(request"]),
        ("One-liner China Chopper", "Variantes conocidas de shells de una línea", ["<%eval request(", "<% execute request(", "@eval($_POST", "${@eval($_POST"]),
        ("Familias conocidas", "Marcadores de texto asociados a familias documentadas", ["b374k", "c99shell", "r57shell", "FilesMan", "wso shell", "Web Shell by", "AnonymousFox"])
    ];

    public string Id => "webshell-heuristics";
    public string Version => "1.0.0";

    public bool CanAnalyze(EvidenceItem evidence) =>
        Extensions.Contains(Path.GetExtension(evidence.OriginalFileName), StringComparer.OrdinalIgnoreCase);

    public async Task<AnalyzerOutput> AnalyzeAsync(AnalyzerContext context)
    {
        var text = await ReadBoundedText(context.FilePath, context.CancellationToken);
        var output = new AnalyzerOutput();
        if (string.IsNullOrWhiteSpace(text))
        {
            output.Summary = "Web shell heurístico: archivo vacío o ilegible; sin patrones observados.";
            return output;
        }

        var hits = 0;
        var matches = 0;
        foreach (var signature in Signatures)
        {
            foreach (var pattern in signature.Patterns)
            {
                if (hits >= MaxHits) break;
                var index = text.IndexOf(pattern, StringComparison.OrdinalIgnoreCase);
                if (index < 0) continue;
                hits++;
                matches++;
                Add(output, context, ArtifactKind.Capability, signature.Family, pattern, $"{signature.Description}; coincidencia en offset={index}; heurística: requiere confirmación del analista.", ConfidenceLevel.Inferred);
            }
        }

        if (matches > 0)
        {
            var entropy = ShannonEntropy(text);
            Add(output, context, ArtifactKind.Entropy, "Entropía del guion", entropy.ToString("F4", System.Globalization.CultureInfo.InvariantCulture), $"Calculada sobre {text.Length} caracteres; la ofuscación densa suele elevarla.", ConfidenceLevel.Observed);
            output.Indicators.Add(new CaseIndicator { Type = IndicatorType.Other, Value = "webshell-heuristics", NormalizedValue = "webshell-heuristics", Description = $"{matches} patrón(es) compatibles con web shell observados en {context.Evidence.Identifier}", Confidence = ConfidenceLevel.Inferred, EvidenceIds = [context.Evidence.Id] });
        }

        output.Summary = matches > 0
            ? $"Web shell heurístico: {matches} coincidencia(s) en {Signatures.Length} familia(s) de patrones; confirmación manual requerida; muestra no ejecutada."
            : $"Web shell heurístico: sin coincidencias en {Signatures.Length} familia(s) de patrones; muestra no ejecutada.";
        return output;
    }

    private static async Task<string> ReadBoundedText(string path, CancellationToken token)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, true);
        using var reader = new StreamReader(stream, Encoding.UTF8, true, 81920, leaveOpen: false);
        var buffer = new char[81920];
        var builder = new StringBuilder((int)Math.Min(stream.Length, MaxCharacters));
        while (builder.Length < MaxCharacters)
        {
            var read = await reader.ReadAsync(buffer.AsMemory(0, Math.Min(buffer.Length, MaxCharacters - builder.Length)), token);
            if (read == 0) break;
            builder.Append(buffer, 0, read);
        }
        return builder.ToString();
    }

    private static double ShannonEntropy(string value)
    {
        if (value.Length == 0) return 0;
        var counts = new Dictionary<char, int>();
        foreach (var character in value) counts[character] = counts.GetValueOrDefault(character) + 1;
        double entropy = 0;
        foreach (var count in counts.Values) { var p = (double)count / value.Length; entropy -= p * Math.Log2(p); }
        return entropy;
    }

    private static void Add(AnalyzerOutput output, AnalyzerContext context, ArtifactKind kind, string name, string value, string detail, ConfidenceLevel confidence) => output.Artifacts.Add(new AnalysisArtifact { EvidenceId = context.Evidence.Id, AnalysisRunId = context.AnalysisRunId, Kind = kind, Name = name, Value = value, Context = detail, Confidence = confidence });
}

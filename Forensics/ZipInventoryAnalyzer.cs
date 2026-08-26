using System.Globalization;
using System.IO.Compression;
using System.Security.Cryptography;
using AtlasForense.Models;
using AtlasForense.Services;

namespace AtlasForense.Forensics;

public sealed class ZipInventoryAnalyzer(IArchiveSafetyInspector safetyInspector) : IForensicAnalyzer
{
    private const long MaxEntryHashBytes = 16 * 1024 * 1024;
    private const long MaxTotalHashBytes = 64 * 1024 * 1024;
    private const int MaxTimelineEvents = 5_000;
    public string Id => "zip-forensic-inventory";
    public string Version => "1.0.0";
    public bool CanAnalyze(EvidenceItem evidence) => Path.GetExtension(evidence.OriginalFileName).Equals(".zip", StringComparison.OrdinalIgnoreCase);

    public async Task<AnalyzerOutput> AnalyzeAsync(AnalyzerContext context)
    {
        var safety = await safetyInspector.InspectZipAsync(context.FilePath, context.CancellationToken);
        if (!safety.Safe) throw new InvalidDataException($"El contenedor ZIP no superó la inspección de seguridad: {safety.Message}");

        var output = new AnalyzerOutput();
        long hashBudgetUsed = 0;
        var hashed = 0;
        using var stream = new FileStream(context.FilePath, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.SequentialScan);
        using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: false);
        foreach (var entry in archive.Entries)
        {
            context.CancellationToken.ThrowIfCancellationRequested();
            var isDirectory = entry.FullName.EndsWith('/');
            var ratio = entry.CompressedLength == 0 ? (entry.Length == 0 ? 0 : double.PositiveInfinity) : (double)entry.Length / entry.CompressedLength;
            var detail = $"comprimido={entry.CompressedLength}; expandido={entry.Length}; razón={(double.IsInfinity(ratio) ? "infinita" : ratio.ToString("F2", CultureInfo.InvariantCulture))}; directorio={isDirectory}";
            Add(output, context, ArtifactKind.Metadata, isDirectory ? "Directorio ZIP" : "Entrada ZIP", entry.FullName, detail);
            if (!isDirectory && entry.Length <= MaxEntryHashBytes && hashBudgetUsed + entry.Length <= MaxTotalHashBytes)
            {
                await using var content = entry.Open();
                var hash = Convert.ToHexString(await SHA256.HashDataAsync(content, context.CancellationToken)).ToLowerInvariant();
                Add(output, context, ArtifactKind.FileHash, "SHA-256 de entrada", hash, $"{entry.FullName}; calculado durante lectura en memoria, sin extracción al disco");
                if (!output.Indicators.Any(x => x.Type == IndicatorType.Hash && x.NormalizedValue == hash))
                    output.Indicators.Add(new CaseIndicator { Type = IndicatorType.Hash, Value = hash, NormalizedValue = hash, Description = entry.FullName, Confidence = ConfidenceLevel.Observed, EvidenceIds = [context.Evidence.Id] });
                hashBudgetUsed += entry.Length;
                hashed++;
            }
            if (output.Events.Count < MaxTimelineEvents && entry.LastWriteTime.Year is >= 1980 and <= 2200)
            {
                var wallClockAsUtc = new DateTimeOffset(DateTime.SpecifyKind(entry.LastWriteTime.DateTime, DateTimeKind.Unspecified), TimeSpan.Zero);
                output.Events.Add(new TimelineEvent { EvidenceId = context.Evidence.Id, OccurredAtUtc = wallClockAsUtc, Category = "Archivo ZIP", Title = entry.FullName, Description = $"{detail}; zona horaria ZIP no disponible, valor de pared representado como UTC", Source = $"{context.Evidence.Identifier}/zip-central-directory", Confidence = ConfidenceLevel.Inferred });
            }
        }
        Add(output, context, ArtifactKind.Metadata, "Presupuesto de hashing ZIP", hashBudgetUsed.ToString(CultureInfo.InvariantCulture), $"bytes leídos; máximo={MaxTotalHashBytes}; entradas con hash={hashed}");
        output.Summary = $"ZIP seguro: {safety.EntryCount} entrada(s), {safety.ExpandedBytes} bytes expandidos declarados, {hashed} hash(es) internos; inventario sin extracción al disco.";
        return output;
    }

    private static void Add(AnalyzerOutput output, AnalyzerContext context, ArtifactKind kind, string name, string value, string detail) =>
        output.Artifacts.Add(new AnalysisArtifact { EvidenceId = context.Evidence.Id, AnalysisRunId = context.AnalysisRunId, Kind = kind, Name = name, Value = value, Context = detail, Confidence = ConfidenceLevel.Observed });
}

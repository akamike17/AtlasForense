using System.Security.Cryptography;
using System.Text;
using AtlasForense.Models;

namespace AtlasForense.Services;

public sealed class MarkdownForensicReportBuilder : IForensicReportBuilder
{
    public ForensicReportDocument BuildMarkdown(ForensicCase item)
    {
        if (item.Report is null) throw new InvalidOperationException("El expediente todavía no tiene un informe sellado.");
        var report = item.Report;
        var text = new StringBuilder();
        text.AppendLine($"# Informe técnico forense — {Escape(item.Title)}").AppendLine();
        text.AppendLine($"**Folio:** {Escape(item.Folio)}  ");
        text.AppendLine($"**Organización solicitante:** {Escape(item.RequestingOrganization)}  ");
        text.AppendLine($"**Perito responsable:** {Escape(item.LeadExaminer)}  ");
        text.AppendLine($"**Preparado por:** {Escape(report.PreparedBy)}  ");
        text.AppendLine($"**Fecha UTC:** {report.PreparedAtUtc:O}  ");
        text.AppendLine($"**SHA-256 del informe sellado:** `{report.IntegrityHash}`").AppendLine();

        Section(text, "1. Resumen ejecutivo", report.ExecutiveSummary);
        Section(text, "2. Alcance y autorización", item.Scope);
        if (item.Authorization is not null)
        {
            text.AppendLine($"- Autoridad: {Escape(item.Authorization.Authority)}");
            text.AppendLine($"- Referencia: {Escape(item.Authorization.Reference)}");
            text.AppendLine($"- Aprobó: {Escape(item.Authorization.ApprovedBy)}");
            text.AppendLine($"- Fecha UTC: {item.Authorization.ApprovedAtUtc:O}");
            text.AppendLine($"- Limitaciones: {Escape(item.Authorization.Limitations)}").AppendLine();
        }
        Section(text, "3. Metodología", report.Methodology);

        text.AppendLine("## 4. Inventario y preservación de evidencia").AppendLine();
        text.AppendLine("| ID | Archivo original | Tamaño | SHA-256 | Adquisición UTC | Método |");
        text.AppendLine("|---|---|---:|---|---|---|");
        foreach (var evidence in item.Evidence.OrderBy(x => x.Identifier))
            text.AppendLine($"| {Cell(evidence.Identifier)} | {Cell(evidence.OriginalFileName)} | {evidence.SizeBytes} | `{evidence.Sha256}` | {evidence.AcquiredAtUtc:O} | {Cell(evidence.AcquisitionMethod)} |");
        text.AppendLine();

        text.AppendLine("## 5. Ejecuciones de análisis").AppendLine();
        foreach (var run in item.AnalysisRuns.OrderBy(x => x.StartedAtUtc))
        {
            var evidence = item.Evidence.FirstOrDefault(x => x.Id == run.EvidenceId)?.Identifier ?? run.EvidenceId.ToString();
            text.AppendLine($"- **{Escape(run.AnalyzerId)} {Escape(run.AnalyzerVersion)}** sobre {Escape(evidence)} — {(run.Success ? "Completado" : "Fallido")}; red bloqueada: {YesNo(run.NetworkBlocked)}; muestra ejecutada: {YesNo(run.SampleExecuted)}; {Escape(run.Summary)}");
        }
        if (item.AnalysisRuns.Count == 0) text.AppendLine("No se registraron ejecuciones automatizadas.");
        text.AppendLine();

        text.AppendLine("## 6. Indicadores y artefactos relevantes").AppendLine();
        text.AppendLine("| Tipo | Valor | Confianza | Evidencia vinculada |");
        text.AppendLine("|---|---|---|---|");
        foreach (var indicator in item.Indicators.OrderBy(x => x.Type).ThenBy(x => x.Value))
            text.AppendLine($"| {indicator.Type} | {Cell(indicator.Value)} | {indicator.Confidence} | {Cell(string.Join(", ", indicator.EvidenceIds.Select(id => item.Evidence.FirstOrDefault(e => e.Id == id)?.Identifier ?? id.ToString())))} |");
        text.AppendLine();

        text.AppendLine("### Capas decodificadas").AppendLine();
        var decoded = item.Artifacts.Where(x => x.Kind == ArtifactKind.DecodedContent).OrderBy(x => x.CreatedAtUtc).ToList();
        if (decoded.Count == 0) text.AppendLine("No se registraron capas codificadas reconocibles.");
        foreach (var artifact in decoded)
        {
            var evidence = item.Evidence.FirstOrDefault(x => x.Id == artifact.EvidenceId)?.Identifier ?? artifact.EvidenceId.ToString();
            text.AppendLine($"- **{Escape(artifact.Name)}** en {Escape(evidence)} — {Escape(artifact.Context)}");
        }
        text.AppendLine();

        text.AppendLine("## 7. Hallazgos").AppendLine();
        var number = 1;
        foreach (var finding in item.Findings.OrderByDescending(x => x.Severity).ThenBy(x => x.CreatedAtUtc))
        {
            text.AppendLine($"### 7.{number++} {Escape(finding.Title)} — {finding.Severity}").AppendLine();
            text.AppendLine(Escape(finding.Description)).AppendLine();
            text.AppendLine($"**Detalle técnico:** {Escape(finding.TechnicalDetails)}  ");
            text.AppendLine($"**Referencias:** {Escape(finding.EvidenceReferences)}  ");
            text.AppendLine($"**Analista:** {Escape(finding.Analyst)}").AppendLine();
        }

        Section(text, "8. Conclusiones", report.Conclusions);
        Section(text, "9. Recomendaciones", report.Recommendations);

        text.AppendLine("## 10. Cadena de custodia").AppendLine();
        foreach (var evidence in item.Evidence.OrderBy(x => x.Identifier))
        {
            text.AppendLine($"### {Escape(evidence.Identifier)}").AppendLine();
            foreach (var custody in evidence.ChainOfCustody.OrderBy(x => x.OccurredAtUtc))
                text.AppendLine($"- {custody.OccurredAtUtc:O} — **{Escape(custody.Action)}**, {Escape(custody.PerformedBy)}, {Escape(custody.Location)}. {Escape(custody.Notes)}");
            text.AppendLine();
        }

        text.AppendLine("## 11. Manifiesto de integridad").AppendLine();
        text.AppendLine("```text");
        foreach (var evidence in item.Evidence.OrderBy(x => x.Identifier)) text.AppendLine($"{evidence.Sha256}  {evidence.Identifier}/{evidence.OriginalFileName}");
        text.AppendLine($"{report.IntegrityHash}  {item.Folio}/sealed-report");
        text.AppendLine("```").AppendLine();
        text.AppendLine($"Cadena de auditoría: **{(AuditChainIsValid(item) ? "VÁLIDA" : "NO VERIFICABLE")}**; {item.AuditTrail.Count} entradas; cabeza `{item.AuditTrail.LastOrDefault()?.EntryHash ?? "GENESIS"}`.");

        var content = text.ToString().Replace("\r\n", "\n", StringComparison.Ordinal);
        var sha = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(content))).ToLowerInvariant();
        return new ForensicReportDocument($"{SafeFileName(item.Folio)}-informe-forense.md", content, sha);
    }

    private static void Section(StringBuilder text, string title, string content) => text.AppendLine($"## {title}").AppendLine().AppendLine(Escape(content)).AppendLine();
    private static string YesNo(bool value) => value ? "sí" : "no";
    private static string Escape(string? value) => (value ?? string.Empty).Replace("\r", " ").Trim();
    private static string Cell(string? value) => Escape(value).Replace("|", "\\|").Replace("\n", " ");
    private static string SafeFileName(string value) => string.Concat(value.Select(c => char.IsLetterOrDigit(c) || c is '-' or '_' ? c : '-'));

    private static bool AuditChainIsValid(ForensicCase item)
    {
        var previous = "GENESIS";
        foreach (var entry in item.AuditTrail.OrderBy(x => x.Sequence))
        {
            if (entry.PreviousHash != previous) return false;
            var canonical = $"{item.Id}|{entry.Sequence}|{entry.OccurredAtUtc:O}|{entry.Actor}|{entry.Action}|{entry.Detail}|{previous}";
            var expected = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
            if (!expected.Equals(entry.EntryHash, StringComparison.OrdinalIgnoreCase)) return false;
            previous = entry.EntryHash;
        }
        return true;
    }
}

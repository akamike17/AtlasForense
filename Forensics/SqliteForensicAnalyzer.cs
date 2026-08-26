using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;
using AtlasForense.Models;
using AtlasForense.Services;
using Microsoft.Data.Sqlite;

namespace AtlasForense.Forensics;

public sealed partial class SqliteForensicAnalyzer : IForensicAnalyzer
{
    private const int MaxTables = 200;
    private const int MaxColumnsPerTable = 200;
    private const int MaxRowsPerTable = 500;
    private const int MaxArtifacts = 10_000;

    static SqliteForensicAnalyzer() => SqliteRuntime.Initialize();

    public string Id => "sqlite-forensic-inventory";
    public string Version => "1.0.0";

    public bool CanAnalyze(EvidenceItem evidence) =>
        new[] { ".db", ".sqlite", ".sqlite3", ".db3" }.Contains(
            Path.GetExtension(evidence.OriginalFileName), StringComparer.OrdinalIgnoreCase);

    public async Task<AnalyzerOutput> AnalyzeAsync(AnalyzerContext context)
    {
        var output = new AnalyzerOutput();
        try
        {
            var builder = new SqliteConnectionStringBuilder
            {
                DataSource = context.FilePath,
                Mode = SqliteOpenMode.ReadOnly,
                Pooling = false,
                Cache = SqliteCacheMode.Private
            };
            await using var connection = new SqliteConnection(builder.ConnectionString);
            await connection.OpenAsync(context.CancellationToken);
            await ValidateDatabase(connection, context.CancellationToken);

            var tables = await ReadTables(connection, context.CancellationToken);
            foreach (var table in tables.Take(MaxTables))
            {
                context.CancellationToken.ThrowIfCancellationRequested();
                var columns = await ReadColumns(connection, table, context.CancellationToken);
                var inspectedRows = await InspectRows(connection, table, columns, output, context);
                AddArtifact(output, context, ArtifactKind.Metadata, "Tabla SQLite", table,
                    $"{columns.Count} columna(s); {(inspectedRows.Truncated ? "más de " : string.Empty)}{inspectedRows.Count.ToString(CultureInfo.InvariantCulture)} registro(s) observado(s)");
                foreach (var column in columns.Take(MaxColumnsPerTable))
                    AddArtifact(output, context, ArtifactKind.Metadata, "Columna SQLite", $"{table}.{column.Name}",
                        $"tipo={column.Type}; nullable={!column.NotNull}; clavePrimaria={column.PrimaryKey}");
            }

            var inspected = Math.Min(tables.Count, MaxTables);
            output.Summary = $"SQLite en solo lectura: {tables.Count} tabla(s), {inspected} inspeccionada(s), " +
                             $"{output.Artifacts.Count} artefactos, {output.Indicators.Count} indicadores y {output.Events.Count} eventos; sin escrituras ni red.";
            return output;
        }
        catch (SqliteException exception)
        {
            throw new InvalidDataException("La evidencia no es una base SQLite legible o está dañada.", exception);
        }
    }

    private static async Task ValidateDatabase(SqliteConnection connection, CancellationToken token)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA quick_check(1);";
        var result = Convert.ToString(await command.ExecuteScalarAsync(token), CultureInfo.InvariantCulture);
        if (!string.Equals(result, "ok", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException($"La comprobación SQLite falló: {result ?? "sin resultado"}.");
    }

    private static async Task<List<string>> ReadTables(SqliteConnection connection, CancellationToken token)
    {
        var tables = new List<string>();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name LIMIT $limit;";
        command.Parameters.AddWithValue("$limit", MaxTables + 1);
        await using var reader = await command.ExecuteReaderAsync(token);
        while (await reader.ReadAsync(token)) tables.Add(reader.GetString(0));
        return tables;
    }

    private static async Task<List<ColumnInfo>> ReadColumns(SqliteConnection connection, string table, CancellationToken token)
    {
        var columns = new List<ColumnInfo>();
        await using var command = connection.CreateCommand();
        command.CommandText = $"PRAGMA table_info({QuoteIdentifier(table)});";
        await using var reader = await command.ExecuteReaderAsync(token);
        while (await reader.ReadAsync(token) && columns.Count < MaxColumnsPerTable)
            columns.Add(new ColumnInfo(reader.GetString(1), reader.IsDBNull(2) ? string.Empty : reader.GetString(2), reader.GetInt64(3) != 0, reader.GetInt64(5) != 0));
        return columns;
    }

    private static async Task<(int Count, bool Truncated)> InspectRows(SqliteConnection connection, string table, IReadOnlyList<ColumnInfo> columns, AnalyzerOutput output, AnalyzerContext context)
    {
        if (columns.Count == 0 || output.Artifacts.Count >= MaxArtifacts) return (0, false);
        await using var command = connection.CreateCommand();
        command.CommandText = $"SELECT * FROM {QuoteIdentifier(table)} LIMIT $limit;";
        command.Parameters.AddWithValue("$limit", MaxRowsPerTable + 1);
        await using var reader = await command.ExecuteReaderAsync(context.CancellationToken);
        var row = 0;
        var truncated = false;
        while (await reader.ReadAsync(context.CancellationToken) && output.Artifacts.Count < MaxArtifacts)
        {
            row++;
            if (row > MaxRowsPerTable) { truncated = true; break; }
            for (var index = 0; index < reader.FieldCount && output.Artifacts.Count < MaxArtifacts; index++)
            {
                if (reader.IsDBNull(index)) continue;
                var value = reader.GetValue(index);
                if (value is byte[]) continue;
                var text = Convert.ToString(value, CultureInfo.InvariantCulture);
                if (string.IsNullOrWhiteSpace(text) || text.Length > 16_384) continue;
                var source = $"{table}.{reader.GetName(index)} fila {row}";
                ExtractIndicators(text, source, output, context);
                ExtractTimestamp(text, reader.GetName(index), source, output, context);
            }
        }
        return (Math.Min(row, MaxRowsPerTable), truncated);
    }

    private static void ExtractIndicators(string text, string source, AnalyzerOutput output, AnalyzerContext context)
    {
        foreach (Match match in UrlRegex().Matches(text)) AddIndicator(output, context, IndicatorType.Url, ArtifactKind.Url, match.Value.TrimEnd('.', ',', ';', ')', ']', '}', '\'', '"'), source);
        foreach (Match match in EmailRegex().Matches(text)) AddIndicator(output, context, IndicatorType.Email, ArtifactKind.Email, match.Value.ToLowerInvariant(), source);
        foreach (Match match in IpRegex().Matches(text)) if (IPAddress.TryParse(match.Value, out var ip)) AddIndicator(output, context, IndicatorType.IpAddress, ArtifactKind.IpAddress, ip.ToString(), source);
        foreach (Match match in HashRegex().Matches(text)) AddIndicator(output, context, IndicatorType.Hash, ArtifactKind.FileHash, match.Value.ToLowerInvariant(), source);
    }

    private static void ExtractTimestamp(string text, string column, string source, AnalyzerOutput output, AnalyzerContext context)
    {
        if (!TimestampColumnRegex().IsMatch(column)) return;
        if (!DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var timestamp)) return;
        if (timestamp.Year is < 1970 or > 2200) return;
        output.Events.Add(new TimelineEvent { EvidenceId = context.Evidence.Id, OccurredAtUtc = timestamp, Category = "SQLite", Title = column, Description = source, Source = IdForSource(context), Confidence = ConfidenceLevel.Observed });
    }

    private static void AddIndicator(AnalyzerOutput output, AnalyzerContext context, IndicatorType type, ArtifactKind kind, string value, string source)
    {
        if (output.Indicators.Any(x => x.Type == type && x.NormalizedValue.Equals(value, StringComparison.OrdinalIgnoreCase))) return;
        AddArtifact(output, context, kind, type.ToString(), value, source);
        output.Indicators.Add(new CaseIndicator { Type = type, Value = value, NormalizedValue = value.ToLowerInvariant(), Description = source, Confidence = ConfidenceLevel.Observed, EvidenceIds = [context.Evidence.Id] });
    }

    private static void AddArtifact(AnalyzerOutput output, AnalyzerContext context, ArtifactKind kind, string name, string value, string detail) =>
        output.Artifacts.Add(new AnalysisArtifact { EvidenceId = context.Evidence.Id, AnalysisRunId = context.AnalysisRunId, Kind = kind, Name = name, Value = value, Context = detail, Confidence = ConfidenceLevel.Observed });

    private static string QuoteIdentifier(string value) => $"\"{value.Replace("\"", "\"\"")}\"";
    private static string IdForSource(AnalyzerContext context) => $"{context.Evidence.Identifier}/sqlite";
    private sealed record ColumnInfo(string Name, string Type, bool NotNull, bool PrimaryKey);

    [GeneratedRegex(@"https?://[^\s<>\""']+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)] private static partial Regex UrlRegex();
    [GeneratedRegex(@"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)] private static partial Regex EmailRegex();
    [GeneratedRegex(@"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])", RegexOptions.CultureInvariant)] private static partial Regex IpRegex();
    [GeneratedRegex(@"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b", RegexOptions.CultureInvariant)] private static partial Regex HashRegex();
    [GeneratedRegex(@"(?:time|date|created|updated|modified|visited|timestamp)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)] private static partial Regex TimestampColumnRegex();
}

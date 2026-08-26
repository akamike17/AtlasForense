using AtlasForense.Models;
using AtlasForense.Services;
using Microsoft.Data.Sqlite;

namespace AtlasForense.Forensics;

public sealed class BrowserHistoryAnalyzer : IForensicAnalyzer
{
    private const int MaxVisits = 5_000;
    private const int MaxUrlLength = 8_192;
    private static readonly DateTimeOffset WebKitEpoch = new(1601, 1, 1, 0, 0, 0, TimeSpan.Zero);
    public string Id => "browser-history-sqlite";
    public string Version => "1.0.0";

    static BrowserHistoryAnalyzer() => SqliteRuntime.Initialize();

    public bool CanAnalyze(EvidenceItem evidence)
    {
        var name = Path.GetFileName(evidence.OriginalFileName);
        return name.Equals("History", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("History.db", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("places.sqlite", StringComparison.OrdinalIgnoreCase);
    }

    public async Task<AnalyzerOutput> AnalyzeAsync(AnalyzerContext context)
    {
        var output = new AnalyzerOutput();
        try
        {
            var connectionString = new SqliteConnectionStringBuilder { DataSource = context.FilePath, Mode = SqliteOpenMode.ReadOnly, Pooling = false, Cache = SqliteCacheMode.Private }.ConnectionString;
            await using var connection = new SqliteConnection(connectionString);
            await connection.OpenAsync(context.CancellationToken);
            var tables = await ReadTableNames(connection, context.CancellationToken);
            string family;
            int visits;
            if (tables.Contains("urls") && tables.Contains("visits"))
            {
                family = "Chromium";
                visits = await ReadChromium(connection, output, context);
            }
            else if (tables.Contains("moz_places") && tables.Contains("moz_historyvisits"))
            {
                family = "Firefox";
                visits = await ReadFirefox(connection, output, context);
            }
            else throw new InvalidDataException("La base no contiene un esquema de historial Chromium o Firefox reconocido.");

            Add(output, context, ArtifactKind.Metadata, "Familia de navegador", family, "Identificada por tablas del esquema, no por el nombre del archivo.");
            output.Summary = $"Historial {family}: {visits} visita(s), {output.Indicators.Count} URL(s) única(s) y {output.Events.Count} evento(s) normalizados a UTC; lectura acotada y sin red.";
            return output;
        }
        catch (SqliteException exception)
        {
            throw new InvalidDataException("La base de historial no es SQLite válida o está dañada.", exception);
        }
    }

    private static async Task<HashSet<string>> ReadTableNames(SqliteConnection connection, CancellationToken token)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT name FROM sqlite_schema WHERE type='table';";
        await using var reader = await command.ExecuteReaderAsync(token);
        while (await reader.ReadAsync(token)) names.Add(reader.GetString(0));
        return names;
    }

    private static async Task<int> ReadChromium(SqliteConnection connection, AnalyzerOutput output, AnalyzerContext context)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT u.url, COALESCE(u.title, ''), v.visit_time
            FROM visits v JOIN urls u ON u.id = v.url
            ORDER BY v.visit_time LIMIT $limit;
            """;
        command.Parameters.AddWithValue("$limit", MaxVisits);
        return await ReadVisits(command, output, context, value => FromWebKitMicroseconds(value), "Chromium");
    }

    private static async Task<int> ReadFirefox(SqliteConnection connection, AnalyzerOutput output, AnalyzerContext context)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT p.url, COALESCE(p.title, ''), h.visit_date
            FROM moz_historyvisits h JOIN moz_places p ON p.id = h.place_id
            ORDER BY h.visit_date LIMIT $limit;
            """;
        command.Parameters.AddWithValue("$limit", MaxVisits);
        return await ReadVisits(command, output, context, value => FromUnixMicroseconds(value), "Firefox");
    }

    private static async Task<int> ReadVisits(SqliteCommand command, AnalyzerOutput output, AnalyzerContext context, Func<long, DateTimeOffset?> convertTime, string family)
    {
        var count = 0;
        await using var reader = await command.ExecuteReaderAsync(context.CancellationToken);
        while (await reader.ReadAsync(context.CancellationToken))
        {
            count++;
            var url = reader.IsDBNull(0) ? string.Empty : reader.GetString(0);
            if (string.IsNullOrWhiteSpace(url) || url.Length > MaxUrlLength || !Uri.TryCreate(url, UriKind.Absolute, out var uri)) continue;
            var title = reader.IsDBNull(1) ? string.Empty : reader.GetString(1);
            if (title.Length > 1_000) title = title[..1_000] + "…";
            AddUrl(output, context, url, $"{family}; título={title}");
            AddDomain(output, context, uri.Host);
            if (reader.IsDBNull(2)) continue;
            var occurred = convertTime(reader.GetInt64(2));
            if (occurred is null) continue;
            output.Events.Add(new TimelineEvent { EvidenceId = context.Evidence.Id, OccurredAtUtc = occurred.Value, Category = "Navegación web", Title = string.IsNullOrWhiteSpace(title) ? uri.Host : title, Description = url, Source = $"{context.Evidence.Identifier}/{family.ToLowerInvariant()}-history", Confidence = ConfidenceLevel.Observed });
        }
        return count;
    }

    private static DateTimeOffset? FromWebKitMicroseconds(long value)
    {
        try { var result = WebKitEpoch.AddTicks(checked(value * 10)); return result.Year is >= 1993 and <= 2200 ? result : null; }
        catch (ArgumentOutOfRangeException) { return null; }
        catch (OverflowException) { return null; }
    }

    private static DateTimeOffset? FromUnixMicroseconds(long value)
    {
        try { var result = DateTimeOffset.UnixEpoch.AddTicks(checked(value * 10)); return result.Year is >= 1993 and <= 2200 ? result : null; }
        catch (ArgumentOutOfRangeException) { return null; }
        catch (OverflowException) { return null; }
    }

    private static void AddUrl(AnalyzerOutput output, AnalyzerContext context, string value, string detail)
    {
        if (output.Indicators.Any(x => x.Type == IndicatorType.Url && x.NormalizedValue.Equals(value, StringComparison.OrdinalIgnoreCase))) return;
        Add(output, context, ArtifactKind.Url, "URL visitada", value, detail);
        output.Indicators.Add(new CaseIndicator { Type = IndicatorType.Url, Value = value, NormalizedValue = value.ToLowerInvariant(), Description = detail, Confidence = ConfidenceLevel.Observed, EvidenceIds = [context.Evidence.Id] });
    }

    private static void AddDomain(AnalyzerOutput output, AnalyzerContext context, string domain)
    {
        if (string.IsNullOrWhiteSpace(domain) || output.Entities.Any(x => x.Type == "Domain" && x.Value.Equals(domain, StringComparison.OrdinalIgnoreCase))) return;
        output.Entities.Add(new CaseEntity { Type = "Domain", Value = domain.ToLowerInvariant(), DisplayName = domain, Confidence = ConfidenceLevel.Observed, EvidenceIds = [context.Evidence.Id] });
    }

    private static void Add(AnalyzerOutput output, AnalyzerContext context, ArtifactKind kind, string name, string value, string detail) =>
        output.Artifacts.Add(new AnalysisArtifact { EvidenceId = context.Evidence.Id, AnalysisRunId = context.AnalysisRunId, Kind = kind, Name = name, Value = value, Context = detail, Confidence = ConfidenceLevel.Observed });
}

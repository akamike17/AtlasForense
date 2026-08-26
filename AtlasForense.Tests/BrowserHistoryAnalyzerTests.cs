using AtlasForense.Forensics;
using AtlasForense.Models;
using Microsoft.Data.Sqlite;
using Xunit;

namespace AtlasForense.Tests;

public sealed class BrowserHistoryAnalyzerTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"atlas-browser-{Guid.NewGuid():N}.db");

    [Fact]
    public async Task ChromiumHistory_NormalizesWebKitTimeAndCorrelatesDomain()
    {
        var expected = new DateTimeOffset(2025, 2, 3, 4, 5, 6, TimeSpan.Zero);
        var webKitMicroseconds = (expected - new DateTimeOffset(1601, 1, 1, 0, 0, 0, TimeSpan.Zero)).Ticks / 10;
        await CreateDatabase("""
            CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT);
            CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER);
            INSERT INTO urls VALUES(1, 'https://portal.example.test/case?id=7', 'Case portal');
            INSERT INTO visits VALUES(1, 1, $time);
            """, webKitMicroseconds);
        var evidence = new EvidenceItem { Id = Guid.NewGuid(), Identifier = "EV-HISTORY", OriginalFileName = "History" };

        var output = await new BrowserHistoryAnalyzer().AnalyzeAsync(new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), evidence, _path, default));

        Assert.Contains(output.Artifacts, x => x.Name == "Familia de navegador" && x.Value == "Chromium");
        Assert.Contains(output.Indicators, x => x.Type == IndicatorType.Url && x.Value.Contains("portal.example.test"));
        Assert.Contains(output.Entities, x => x.Type == "Domain" && x.Value == "portal.example.test");
        Assert.Contains(output.Events, x => x.OccurredAtUtc == expected && x.Title == "Case portal");
    }

    [Fact]
    public async Task FirefoxHistory_NormalizesUnixMicrosecondsAndDeduplicatesUrls()
    {
        var expected = new DateTimeOffset(2024, 8, 9, 10, 11, 12, TimeSpan.Zero);
        var unixMicroseconds = (expected - DateTimeOffset.UnixEpoch).Ticks / 10;
        await CreateDatabase("""
            CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url TEXT, title TEXT);
            CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER);
            INSERT INTO moz_places VALUES(1, 'https://research.example.org/report', 'Research');
            INSERT INTO moz_historyvisits VALUES(1, 1, $time);
            INSERT INTO moz_historyvisits VALUES(2, 1, $time);
            """, unixMicroseconds);
        var evidence = new EvidenceItem { Id = Guid.NewGuid(), Identifier = "EV-PLACES", OriginalFileName = "places.sqlite" };

        var output = await new BrowserHistoryAnalyzer().AnalyzeAsync(new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), evidence, _path, default));

        Assert.Contains(output.Artifacts, x => x.Name == "Familia de navegador" && x.Value == "Firefox");
        Assert.Single(output.Indicators, x => x.Type == IndicatorType.Url);
        Assert.Equal(2, output.Events.Count);
        Assert.All(output.Events, x => Assert.Equal(expected, x.OccurredAtUtc));
    }

    [Fact]
    public async Task UnknownSchema_IsRejectedInsteadOfGuessing()
    {
        await CreateDatabase("CREATE TABLE unrelated(id INTEGER);", 0);
        var evidence = new EvidenceItem { OriginalFileName = "History" };

        var exception = await Assert.ThrowsAsync<InvalidDataException>(() => new BrowserHistoryAnalyzer().AnalyzeAsync(
            new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), evidence, _path, default)));

        Assert.Contains("no contiene un esquema", exception.Message);
    }

    private async Task CreateDatabase(string sql, long time)
    {
        _ = new BrowserHistoryAnalyzer();
        await using var connection = new SqliteConnection($"Data Source={_path};Pooling=False");
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.Parameters.AddWithValue("$time", time);
        await command.ExecuteNonQueryAsync();
    }

    public void Dispose() { SqliteConnection.ClearAllPools(); if (File.Exists(_path)) File.Delete(_path); }
}

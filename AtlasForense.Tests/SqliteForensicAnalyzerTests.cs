using System.Security.Cryptography;
using AtlasForense.Forensics;
using AtlasForense.Models;
using Microsoft.Data.Sqlite;
using Xunit;

namespace AtlasForense.Tests;

public sealed class SqliteForensicAnalyzerTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"atlas-sqlite-{Guid.NewGuid():N}.db");

    [Fact]
    public async Task Analyzer_InventoriesSchemaAndExtractsIndicatorsAndTimelineWithoutChangingEvidence()
    {
        _ = new SqliteForensicAnalyzer();
        await using (var connection = new SqliteConnection($"Data Source={_path};Pooling=False"))
        {
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = """
                CREATE TABLE browser_history(id INTEGER PRIMARY KEY, url TEXT, account TEXT, visited_at TEXT, digest TEXT);
                INSERT INTO browser_history(url, account, visited_at, digest)
                VALUES ('https://evidence.example.test/path', 'analyst@example.test', '2025-03-04T05:06:07Z', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
                """;
            await command.ExecuteNonQueryAsync();
        }
        var before = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(_path)));
        var evidence = new EvidenceItem { Id = Guid.NewGuid(), Identifier = "EV-001", OriginalFileName = "history.sqlite" };
        var run = Guid.NewGuid();

        var output = await new SqliteForensicAnalyzer().AnalyzeAsync(new AnalyzerContext(Guid.NewGuid(), run, evidence, _path, default));

        var after = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(_path)));
        Assert.Equal(before, after);
        Assert.Contains(output.Artifacts, x => x.Name == "Tabla SQLite" && x.Value == "browser_history");
        Assert.Contains(output.Artifacts, x => x.Name == "Columna SQLite" && x.Value == "browser_history.url");
        Assert.Contains(output.Indicators, x => x.Type == IndicatorType.Url && x.Value == "https://evidence.example.test/path");
        Assert.Contains(output.Indicators, x => x.Type == IndicatorType.Email && x.Value == "analyst@example.test");
        Assert.Contains(output.Indicators, x => x.Type == IndicatorType.Hash && x.Value.Length == 64);
        Assert.Contains(output.Events, x => x.OccurredAtUtc == DateTimeOffset.Parse("2025-03-04T05:06:07Z"));
        Assert.Contains("solo lectura", output.Summary);
    }

    [Theory]
    [InlineData("evidence.txt", false)]
    [InlineData("history.db", true)]
    [InlineData("places.SQLITE", true)]
    public void Compatibility_UsesForensicDatabaseExtensions(string name, bool expected) =>
        Assert.Equal(expected, new SqliteForensicAnalyzer().CanAnalyze(new EvidenceItem { OriginalFileName = name }));

    [Fact]
    public async Task Analyzer_RejectsInvalidDatabaseWithForensicSafeError()
    {
        await File.WriteAllTextAsync(_path, "not a database");
        var analyzer = new SqliteForensicAnalyzer();
        var evidence = new EvidenceItem { OriginalFileName = "corrupt.db" };

        var exception = await Assert.ThrowsAsync<InvalidDataException>(() =>
            analyzer.AnalyzeAsync(new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), evidence, _path, default)));

        Assert.Contains("dañada", exception.Message);
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        if (File.Exists(_path)) File.Delete(_path);
    }
}

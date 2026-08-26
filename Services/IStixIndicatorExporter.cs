using AtlasForense.Models;

namespace AtlasForense.Services;

public interface IStixIndicatorExporter
{
    StixExportResult Export(ForensicCase item);
}

public sealed record StixExportResult(string Content, string FileName, string Sha256, int Indicators, int Skipped);

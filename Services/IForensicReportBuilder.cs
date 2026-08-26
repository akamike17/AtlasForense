using AtlasForense.Models;

namespace AtlasForense.Services;

public sealed record ForensicReportDocument(string FileName, string Content, string Sha256);

public interface IForensicReportBuilder
{
    ForensicReportDocument BuildMarkdown(ForensicCase item);
}

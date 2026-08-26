using AtlasForense.Models;
using AtlasForense.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AtlasForense.Controllers;

[Authorize(Policy = "Audit")]
public sealed class MetricsController(IForensicCaseService cases, IForensicRetention retention) : Controller
{
    [HttpGet]
    public IActionResult Index()
    {
        var all = cases.GetAll();
        return Json(new
        {
            generatedAtUtc = DateTimeOffset.UtcNow,
            cases = new
            {
                total = all.Count,
                byStatus = all.GroupBy(x => x.Status.ToString()).ToDictionary(group => group.Key, group => group.Count())
            },
            evidence = new
            {
                total = all.Sum(x => x.Evidence.Count),
                bytes = all.Sum(x => x.Evidence.Sum(e => e.SizeBytes))
            },
            analysis = new
            {
                runs = all.Sum(x => x.AnalysisRuns.Count),
                failures = all.Sum(x => x.AnalysisRuns.Count(run => !run.Success && !run.Cancelled))
            },
            indicators = all.Sum(x => x.Indicators.Count),
            retention = new
            {
                enabled = retention.Enabled,
                candidates = retention.GetCandidates(DateTimeOffset.UtcNow).Count
            }
        });
    }
}

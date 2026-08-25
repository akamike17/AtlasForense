using AtlasForense.Models;
using AtlasForense.Services;
using Microsoft.AspNetCore.Mvc;

namespace AtlasForense.Controllers;

[AutoValidateAntiforgeryToken]
public sealed class CasesController(IForensicCaseService service, IForensicReportBuilder reportBuilder) : Controller
{
    [HttpGet] public IActionResult Index() => View(service.GetAll());
    [HttpGet] public IActionResult Create() => View(new CreateCaseInput());

    [HttpPost]
    public async Task<IActionResult> Create(CreateCaseInput input, CancellationToken token)
    {
        if (!ModelState.IsValid) return View(input);
        var item = await service.CreateAsync(input, token);
        TempData["Success"] = $"Expediente {item.Folio} creado.";
        return RedirectToAction(nameof(Details), new { id = item.Id });
    }

    [HttpGet]
    public IActionResult Details(Guid id)
    {
        var item = service.Get(id);
        return item is null ? NotFound() : View(item);
    }

    [HttpPost] public Task<IActionResult> Authorize(AuthorizeCaseInput input, CancellationToken token) => Execute(input.CaseId, () => service.AuthorizeAsync(input, token));

    [HttpPost, RequestSizeLimit(104_857_600)]
    public Task<IActionResult> Acquire(AcquireEvidenceInput input, CancellationToken token)
    {
        if (!ModelState.IsValid) return Invalid(input.CaseId);
        return Execute(input.CaseId, () => service.AcquireAsync(input, token));
    }

    [HttpPost] public Task<IActionResult> AddCustody(CustodyInput input, CancellationToken token) => Execute(input.CaseId, () => service.AddCustodyAsync(input, token));
    [HttpPost] public Task<IActionResult> StartAnalysis(Guid id, string actor, CancellationToken token) => Execute(id, () => service.StartAnalysisAsync(id, actor, token));
    [HttpPost] public Task<IActionResult> AnalyzeEvidence(Guid caseId, Guid evidenceId, string actor, CancellationToken token) => Execute(caseId, () => service.AnalyzeEvidenceAsync(caseId, evidenceId, actor, token));

    [HttpPost]
    public Task<IActionResult> AddFinding(FindingInput input, CancellationToken token)
    {
        if (!ModelState.IsValid) return Invalid(input.CaseId);
        return Execute(input.CaseId, () => service.AddFindingAsync(input, token));
    }

    [HttpPost]
    public Task<IActionResult> PrepareReport(ReportInput input, CancellationToken token)
    {
        if (!ModelState.IsValid) return Invalid(input.CaseId);
        return Execute(input.CaseId, () => service.PrepareReportAsync(input, token));
    }

    [HttpPost] public Task<IActionResult> Close(Guid id, string actor, CancellationToken token) => Execute(id, () => service.CloseAsync(id, actor, token));

    [HttpGet]
    public IActionResult Report(Guid id)
    {
        var item = service.Get(id);
        return item?.Report is null ? NotFound() : View(item);
    }

    [HttpGet]
    public IActionResult ExportMarkdown(Guid id)
    {
        var item = service.Get(id);
        if (item?.Report is null) return NotFound();
        var document = reportBuilder.BuildMarkdown(item);
        Response.Headers.Append("X-Content-SHA256", document.Sha256);
        return File(System.Text.Encoding.UTF8.GetBytes(document.Content), "text/markdown; charset=utf-8", document.FileName);
    }

    private async Task<IActionResult> Execute(Guid id, Func<Task<OperationResult>> operation)
    {
        var result = await operation();
        TempData[result.Success ? "Success" : "Error"] = result.Message;
        return RedirectToAction(nameof(Details), new { id });
    }

    private Task<IActionResult> Invalid(Guid id)
    {
        TempData["Error"] = string.Join(" ", ModelState.Values.SelectMany(x => x.Errors).Select(x => x.ErrorMessage));
        return Task.FromResult<IActionResult>(RedirectToAction(nameof(Details), new { id }));
    }
}

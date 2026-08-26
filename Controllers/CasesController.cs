using AtlasForense.Models;
using AtlasForense.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace AtlasForense.Controllers;

[AutoValidateAntiforgeryToken]
public sealed class CasesController(IForensicCaseService service, IForensicReportBuilder reportBuilder, IForensicPackageBuilder packageBuilder, IUserAccountService accounts) : Controller
{
    [HttpGet] public IActionResult Index() => View(User.IsInRole(nameof(ForensicRole.Administrator)) ? service.GetAll() : service.GetAll().Where(HasAnyCaseAccess).ToList());
    [HttpGet, Authorize(Policy = "Examine")] public IActionResult Create() => View(new CreateCaseInput());

    [HttpPost, Authorize(Policy = "Examine")]
    public async Task<IActionResult> Create(CreateCaseInput input, CancellationToken token)
    {
        if (!ModelState.IsValid) return View(input);
        input.LeadExaminer = Actor;
        input.ActorUserId = ActorUserId;
        var item = await service.CreateAsync(input, token);
        TempData["Success"] = $"Expediente {item.Folio} creado.";
        return RedirectToAction(nameof(Details), new { id = item.Id });
    }

    [HttpGet]
    public IActionResult Details(Guid id)
    {
        var item = service.Get(id);
        if (item is null) return NotFound();
        if (!HasAnyCaseAccess(item)) return Forbid();
        ViewBag.AssignableUsers = accounts.GetAll().Where(x => x.Enabled && x.Role != ForensicRole.Administrator).ToList();
        return View(item);
    }

    [HttpPost, Authorize(Policy = "AuthorizeCase")] public Task<IActionResult> Authorize(AuthorizeCaseInput input, CancellationToken token) { input.ApprovedBy = Actor; return Execute(input.CaseId, () => service.AuthorizeAsync(input, token), ForensicRole.Examiner); }

    [HttpPost, Authorize(Policy = "Examine")]
    public Task<IActionResult> Acquire(AcquireEvidenceInput input, CancellationToken token)
    {
        input.AcquiredBy = Actor;
        if (!ModelState.IsValid) return Invalid(input.CaseId);
        return Execute(input.CaseId, () => service.AcquireAsync(input, token), ForensicRole.Examiner);
    }

    [HttpPost, Authorize(Policy = "Custody")] public Task<IActionResult> AddCustody(CustodyInput input, CancellationToken token) { input.PerformedBy = Actor; return Execute(input.CaseId, () => service.AddCustodyAsync(input, token), ForensicRole.Custodian); }
    [HttpPost, Authorize(Policy = "Examine")] public Task<IActionResult> StartAnalysis(Guid id, CancellationToken token) => Execute(id, () => service.StartAnalysisAsync(id, Actor, token), ForensicRole.Examiner);
    [HttpPost, Authorize(Policy = "Examine")] public Task<IActionResult> AnalyzeEvidence(Guid caseId, Guid evidenceId, CancellationToken token) => Execute(caseId, () => service.AnalyzeEvidenceAsync(caseId, evidenceId, Actor, token), ForensicRole.Examiner);

    [HttpPost, Authorize(Policy = "Examine")]
    public Task<IActionResult> AddFinding(FindingInput input, CancellationToken token)
    {
        input.Analyst = Actor;
        if (!ModelState.IsValid) return Invalid(input.CaseId);
        return Execute(input.CaseId, () => service.AddFindingAsync(input, token), ForensicRole.Examiner);
    }

    [HttpPost, Authorize(Policy = "Examine")]
    public Task<IActionResult> PrepareReport(ReportInput input, CancellationToken token)
    {
        input.PreparedBy = Actor;
        if (!ModelState.IsValid) return Invalid(input.CaseId);
        return Execute(input.CaseId, () => service.PrepareReportAsync(input, token), ForensicRole.Examiner);
    }

    [HttpPost, Authorize(Policy = "Review")] public Task<IActionResult> ReviewReport(Guid id, bool approve, string notes, CancellationToken token) => Execute(id, () => service.ReviewReportAsync(id, Actor, approve, notes, token), ForensicRole.Reviewer);

    [HttpPost, Authorize(Policy = "CloseCase")] public Task<IActionResult> Close(Guid id, CancellationToken token) => Execute(id, () => service.CloseAsync(id, Actor, token), ForensicRole.Reviewer);

    [HttpPost, Authorize(Policy = "ReopenCase")]
    public Task<IActionResult> Reopen(Guid id, string reason, CancellationToken token) => Execute(id, () => service.ReopenAsync(id, Actor, reason, token));

    [HttpPost, Authorize(Policy = "AdministerUsers")]
    public Task<IActionResult> AssignUser(CaseAssignmentInput input, CancellationToken token)
    {
        var user = accounts.GetById(input.UserId);
        if (user is null || !user.Enabled || user.Role != input.Role) { TempData["Error"] = "El usuario debe existir, estar habilitado y tener el mismo rol global."; return Task.FromResult<IActionResult>(RedirectToAction(nameof(Details), new { id = input.CaseId })); }
        return Execute(input.CaseId, () => service.AssignUserAsync(input, ActorUserId, Actor, token));
    }

    [HttpGet]
    public IActionResult Report(Guid id)
    {
        var item = service.Get(id);
        return item?.Report is null ? NotFound() : HasAnyCaseAccess(item) ? View(item) : Forbid();
    }

    [HttpGet]
    public IActionResult ExportMarkdown(Guid id)
    {
        var item = service.Get(id);
        if (item?.Report is null) return NotFound();
        if (!HasAnyCaseAccess(item)) return Forbid();
        var document = reportBuilder.BuildMarkdown(item);
        Response.Headers.Append("X-Content-SHA256", document.Sha256);
        return File(System.Text.Encoding.UTF8.GetBytes(document.Content), "text/markdown; charset=utf-8", document.FileName);
    }

    [HttpGet, Authorize(Policy = "ExportCase")]
    public async Task<IActionResult> ExportPackage(Guid id, CancellationToken token)
    {
        var item = service.Get(id);
        if (item is null) return NotFound();
        if (!HasAnyCaseAccess(item)) return Forbid();
        var result = await packageBuilder.BuildAsync(item, token);
        if (!result.Success) { TempData["Error"] = result.Message; return RedirectToAction(nameof(Details), new { id }); }
        Response.Headers.Append("X-Content-SHA256", result.Sha256);
        Response.Headers.Append("X-Signer-Certificate-SHA256", result.CertificateSha256);
        var stream = new FileStream(result.Path, FileMode.Open, FileAccess.Read, FileShare.Read, 131072, FileOptions.Asynchronous | FileOptions.SequentialScan | FileOptions.DeleteOnClose);
        return File(stream, "application/vnd.atlasforense.package+zip", result.FileName);
    }

    private async Task<IActionResult> Execute(Guid id, Func<Task<OperationResult>> operation, params ForensicRole[] requiredRoles)
    {
        var item = service.Get(id);
        if (item is null) return NotFound();
        if (requiredRoles.Length > 0 && !User.IsInRole(nameof(ForensicRole.Administrator)) && !item.Assignments.Any(x => x.Active && x.UserId == ActorUserId && requiredRoles.Contains(x.Role))) return Forbid();
        var result = await operation();
        TempData[result.Success ? "Success" : "Error"] = result.Message;
        return RedirectToAction(nameof(Details), new { id });
    }

    private Task<IActionResult> Invalid(Guid id)
    {
        TempData["Error"] = string.Join(" ", ModelState.Values.SelectMany(x => x.Errors).Select(x => x.ErrorMessage));
        return Task.FromResult<IActionResult>(RedirectToAction(nameof(Details), new { id }));
    }

    private string Actor => User.FindFirst("display_name")?.Value ?? User.Identity?.Name ?? throw new InvalidOperationException("No existe identidad autenticada.");
    private Guid ActorUserId => Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
    private bool HasAnyCaseAccess(ForensicCase item) => User.IsInRole(nameof(ForensicRole.Administrator)) || item.Assignments.Any(x => x.Active && x.UserId == ActorUserId);
}

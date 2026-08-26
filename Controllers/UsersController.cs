using System.Security.Claims;
using AtlasForense.Models;
using AtlasForense.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AtlasForense.Controllers;

[Authorize(Policy = "AdministerUsers"), AutoValidateAntiforgeryToken]
public sealed class UsersController(IUserAccountService accounts) : Controller
{
    [HttpGet] public IActionResult Index() => View(accounts.GetAll());
    [HttpGet] public IActionResult Create() => View(new CreateUserInput());

    [HttpPost]
    public async Task<IActionResult> Create(CreateUserInput input, CancellationToken token)
    {
        if (!ModelState.IsValid) return View(input);
        var result = await accounts.CreateUserAsync(CurrentUserId, input, token);
        if (!result.Success) { ModelState.AddModelError(string.Empty, result.Message); return View(input); }
        return View("Provisioned", result);
    }

    [HttpPost]
    public async Task<IActionResult> SetEnabled(Guid id, bool enabled, CancellationToken token)
    {
        TempData[await accounts.SetEnabledAsync(CurrentUserId, id, enabled, token) ? "Success" : "Error"] = enabled ? "Usuario habilitado." : "Usuario deshabilitado y sesiones revocadas.";
        return RedirectToAction(nameof(Index));
    }

    private Guid CurrentUserId => Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
}

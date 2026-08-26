using System.Security.Claims;
using AtlasForense.Models;
using AtlasForense.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AtlasForense.Controllers;

[AutoValidateAntiforgeryToken]
public sealed class AccountController(IUserAccountService accounts) : Controller
{
    [AllowAnonymous, HttpGet]
    public IActionResult Setup()
    {
        if (accounts.HasUsers()) return RedirectToAction(nameof(Login));
        return View(NewSetupModel());
    }

    [AllowAnonymous, HttpPost]
    public async Task<IActionResult> Setup(BootstrapViewModel model, CancellationToken token)
    {
        if (accounts.HasUsers()) return Conflict("La configuración inicial ya fue completada.");
        if (!ModelState.IsValid) return View(NewSetupModel(model.Input));
        var result = await accounts.BootstrapAsync(model.Input, token);
        if (!result.Success || result.User is null)
        {
            ModelState.AddModelError(string.Empty, result.Message);
            return View(NewSetupModel(model.Input));
        }
        await SignInUserAsync(result.User);
        return View("RecoveryCodes", result.RecoveryCodes);
    }

    [AllowAnonymous, HttpGet]
    public IActionResult Login(string? returnUrl = null)
    {
        if (!accounts.HasUsers()) return RedirectToAction(nameof(Setup));
        if (User.Identity?.IsAuthenticated == true) return RedirectToLocal(returnUrl);
        return View(new LoginInput { ReturnUrl = LocalReturnUrl(returnUrl) });
    }

    [AllowAnonymous, HttpPost]
    public async Task<IActionResult> Login(LoginInput input, CancellationToken token)
    {
        input.ReturnUrl = LocalReturnUrl(input.ReturnUrl);
        if (!ModelState.IsValid) return View(input);
        var result = await accounts.AuthenticateAsync(input.UserName, input.Password, input.MfaCode, token);
        if (!result.Success || result.User is null)
        {
            ModelState.AddModelError(string.Empty, result.Message);
            return View(input);
        }
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        await SignInUserAsync(result.User);
        if (result.UsedRecoveryCode) TempData["Warning"] = "Se utilizó un código de recuperación. Genere un nuevo conjunto cuanto antes.";
        if (result.User.MustChangePassword) return RedirectToAction(nameof(ChangePassword));
        return RedirectToLocal(input.ReturnUrl);
    }

    [Authorize, HttpPost]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToAction(nameof(Login));
    }

    [AllowAnonymous, HttpGet]
    public IActionResult AccessDenied() => View();

    [Authorize, HttpGet]
    public IActionResult ChangePassword() => View(new ChangePasswordInput());

    [Authorize, HttpPost]
    public async Task<IActionResult> ChangePassword(ChangePasswordInput input, CancellationToken token)
    {
        if (!ModelState.IsValid) return View(input);
        var id = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var result = await accounts.ChangePasswordAsync(id, input, token);
        if (!result.Success) { ModelState.AddModelError(string.Empty, result.Message); return View(input); }
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        TempData["Success"] = result.Message;
        return RedirectToAction(nameof(Login));
    }

    private BootstrapViewModel NewSetupModel(BootstrapInput? previous = null)
    {
        var challenge = accounts.CreateBootstrapChallenge();
        return new BootstrapViewModel
        {
            Input = new BootstrapInput { UserName = previous?.UserName ?? string.Empty, DisplayName = previous?.DisplayName ?? string.Empty, Challenge = challenge.Challenge },
            Secret = challenge.Secret, ExpiresAtUtc = challenge.ExpiresAtUtc
        };
    }

    private async Task SignInUserAsync(AppUser user)
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString("D")), new Claim(ClaimTypes.Name, user.UserName),
            new Claim("display_name", user.DisplayName), new Claim(ClaimTypes.Role, user.Role.ToString()),
            new Claim("security_stamp", user.SecurityStamp)
        };
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme));
        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal, new AuthenticationProperties
        {
            IsPersistent = false, AllowRefresh = false, IssuedUtc = DateTimeOffset.UtcNow, ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(30)
        });
    }

    private string LocalReturnUrl(string? value) => !string.IsNullOrWhiteSpace(value) && Url.IsLocalUrl(value) ? value : string.Empty;
    private IActionResult RedirectToLocal(string? value) => Redirect(LocalReturnUrl(value) is { Length: > 0 } local ? local : Url.Action("Index", "Cases")!);
}

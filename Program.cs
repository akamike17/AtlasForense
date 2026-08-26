using AtlasForense.Services;
using AtlasForense.Forensics;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews(options => options.MaxModelValidationErrors = 100);
var keyPath = Path.Combine(builder.Environment.ContentRootPath, "App_Data", "Keys");
Directory.CreateDirectory(keyPath);
var dataProtection = builder.Services.AddDataProtection()
    .SetApplicationName("AtlasForense")
    .PersistKeysToFileSystem(new DirectoryInfo(keyPath));
if (OperatingSystem.IsWindows() && !builder.Environment.IsEnvironment("Testing")) dataProtection.ProtectKeysWithDpapi();
builder.Services.AddSingleton<IUserAccountService, SqliteUserAccountService>();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Account/Login";
        options.AccessDeniedPath = "/Account/AccessDenied";
        options.Cookie.Name = "__Host-AtlasForense";
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Strict;
        options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
        options.SlidingExpiration = false;
        options.Events = new CookieAuthenticationEvents
        {
            OnRedirectToLogin = context =>
            {
                if (IsApiRequest(context.Request)) { context.Response.StatusCode = StatusCodes.Status401Unauthorized; return Task.CompletedTask; }
                context.Response.Redirect(context.RedirectUri); return Task.CompletedTask;
            },
            OnRedirectToAccessDenied = context =>
            {
                if (IsApiRequest(context.Request)) { context.Response.StatusCode = StatusCodes.Status403Forbidden; return Task.CompletedTask; }
                context.Response.Redirect(context.RedirectUri); return Task.CompletedTask;
            },
            OnValidatePrincipal = context =>
            {
                var idValue = context.Principal?.FindFirstValue(ClaimTypes.NameIdentifier);
                var stamp = context.Principal?.FindFirstValue("security_stamp");
                var service = context.HttpContext.RequestServices.GetRequiredService<IUserAccountService>();
                var user = Guid.TryParse(idValue, out var id) ? service.GetById(id) : null;
                if (user is null || !user.Enabled || !CryptographicOperations.FixedTimeEquals(
                    System.Text.Encoding.UTF8.GetBytes(user.SecurityStamp), System.Text.Encoding.UTF8.GetBytes(stamp ?? string.Empty)))
                {
                    context.RejectPrincipal();
                    return context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                }
                return Task.CompletedTask;
            }
        };
    });
builder.Services.AddAuthorization(options =>
{
    options.FallbackPolicy = new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
    options.AddPolicy("AdministerUsers", policy => policy.RequireRole(nameof(AtlasForense.Models.ForensicRole.Administrator)));
    options.AddPolicy("Examine", policy => policy.RequireRole(nameof(AtlasForense.Models.ForensicRole.Administrator), nameof(AtlasForense.Models.ForensicRole.Examiner)));
    options.AddPolicy("AuthorizeCase", policy => policy.RequireRole(nameof(AtlasForense.Models.ForensicRole.Administrator), nameof(AtlasForense.Models.ForensicRole.Examiner)));
    options.AddPolicy("Review", policy => policy.RequireRole(nameof(AtlasForense.Models.ForensicRole.Administrator), nameof(AtlasForense.Models.ForensicRole.Reviewer)));
    options.AddPolicy("CloseCase", policy => policy.RequireRole(nameof(AtlasForense.Models.ForensicRole.Administrator), nameof(AtlasForense.Models.ForensicRole.Reviewer)));
    options.AddPolicy("Custody", policy => policy.RequireRole(nameof(AtlasForense.Models.ForensicRole.Administrator), nameof(AtlasForense.Models.ForensicRole.Custodian)));
    options.AddPolicy("Audit", policy => policy.RequireRole(Enum.GetNames<AtlasForense.Models.ForensicRole>()));
});
builder.Services.AddSingleton<IForensicCaseService, JsonForensicCaseService>();
builder.Services.AddSingleton<IForensicDataMaintenance>(provider =>
    (JsonForensicCaseService)provider.GetRequiredService<IForensicCaseService>());
builder.Services.AddSingleton<IForensicReportBuilder, MarkdownForensicReportBuilder>();
builder.Services.AddSingleton<IContentTransformationService, ContentTransformationService>();
builder.Services.AddSingleton<IForensicAnalyzer, StaticTextAnalyzer>();
builder.Services.AddSingleton<IForensicAnalyzer, BinaryMetadataAnalyzer>();
builder.Services.Configure<FormOptions>(options => options.MultipartBodyLengthLimit = 104_857_600);
builder.Services.AddHealthChecks();
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions { PermitLimit = 120, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
});

var app = builder.Build();

var maintenanceCommand = args.FirstOrDefault(argument => argument.StartsWith("--data-", StringComparison.OrdinalIgnoreCase));
if (maintenanceCommand is not null)
{
    var maintenance = app.Services.GetRequiredService<IForensicDataMaintenance>();
    switch (maintenanceCommand.ToLowerInvariant())
    {
        case "--data-verify":
        {
            var result = await maintenance.VerifyAsync(CancellationToken.None);
            Console.WriteLine($"{result.Message} Expedientes: {result.CaseCount}.");
            Environment.ExitCode = result.Success ? 0 : 2;
            return;
        }
        case "--data-backup":
        {
            var result = await maintenance.CreateBackupAsync(CancellationToken.None);
            Console.WriteLine($"{result.Message} Archivo: {result.FileName}; SHA-256: {result.Sha256}; expedientes: {result.CaseCount}.");
            Environment.ExitCode = result.Success ? 0 : 2;
            return;
        }
        case "--data-restore":
        {
            var index = Array.FindIndex(args, argument => argument.Equals(maintenanceCommand, StringComparison.OrdinalIgnoreCase));
            var fileName = index >= 0 && index + 1 < args.Length ? args[index + 1] : string.Empty;
            var result = await maintenance.RestoreBackupAsync(fileName, CancellationToken.None);
            Console.WriteLine($"{result.Message} Expedientes: {result.CaseCount}.");
            Environment.ExitCode = result.Success ? 0 : 2;
            return;
        }
        default:
            Console.Error.WriteLine("Comando desconocido. Use --data-verify, --data-backup o --data-restore <archivo>.");
            Environment.ExitCode = 2;
            return;
    }
}

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.Use(async (context, next) =>
{
    context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Append("X-Frame-Options", "DENY");
    context.Response.Headers.Append("Referrer-Policy", "no-referrer");
    context.Response.Headers.Append("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    context.Response.Headers.Append("Content-Security-Policy", "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'");
    await next();
});
app.UseStaticFiles();

app.UseRouting();
app.UseRateLimiter();

app.UseAuthentication();
app.Use(async (context, next) =>
{
    if (context.User.Identity?.IsAuthenticated == true &&
        Guid.TryParse(context.User.FindFirstValue(ClaimTypes.NameIdentifier), out var userId) &&
        context.RequestServices.GetRequiredService<IUserAccountService>().GetById(userId)?.MustChangePassword == true &&
        !context.Request.Path.StartsWithSegments("/Account/ChangePassword", StringComparison.OrdinalIgnoreCase) &&
        !context.Request.Path.StartsWithSegments("/Account/Logout", StringComparison.OrdinalIgnoreCase))
    {
        if (IsApiRequest(context.Request)) context.Response.StatusCode = StatusCodes.Status403Forbidden;
        else context.Response.Redirect("/Account/ChangePassword");
        return;
    }
    await next();
});
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");
app.MapHealthChecks("/healthz");

app.Run();

static bool IsApiRequest(HttpRequest request) =>
    request.Path.StartsWithSegments("/api", StringComparison.OrdinalIgnoreCase) ||
    request.Headers.Accept.Any(value => value?.Contains("application/json", StringComparison.OrdinalIgnoreCase) == true) ||
    string.Equals(request.Headers["X-Requested-With"], "XMLHttpRequest", StringComparison.OrdinalIgnoreCase);

public partial class Program;

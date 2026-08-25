using AtlasForense.Services;
using AtlasForense.Forensics;
using Microsoft.AspNetCore.Http.Features;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews(options => options.MaxModelValidationErrors = 100);
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

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");
app.MapHealthChecks("/healthz");

app.Run();

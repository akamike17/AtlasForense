using System.Diagnostics;
using System.Net;
using System.Text;
using AtlasForense.Models;
using AtlasForense.Services;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Logging;
using Xunit;

namespace AtlasForense.Tests;

public sealed class LoadAndConcurrencyTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"atlas-load-{Guid.NewGuid():N}");
    private readonly WebApplicationFactory<Program> _factory;

    public LoadAndConcurrencyTests()
    {
        Directory.CreateDirectory(_root);
        _factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Testing").UseContentRoot(_root);
            builder.ConfigureLogging(logging => logging.ClearProviders().AddDebug());
        });
    }

    [Fact]
    public async Task HttpLoad_100ConcurrentAnonymousRequests_AllSucceedWithoutServerError()
    {
        await BootstrapAdministrator();
        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false, BaseAddress = new Uri("https://localhost") });
        var stopwatch = Stopwatch.StartNew();
        var tasks = Enumerable.Range(0, 100).Select(_ => client.GetAsync("/Account/Login")).ToArray();
        var responses = await Task.WhenAll(tasks);
        stopwatch.Stop();

        Assert.All(responses, response => Assert.Equal(HttpStatusCode.OK, response.StatusCode));
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(30), $"100 solicitudes concurrentes tardaron {stopwatch.Elapsed}.");
    }

    private async Task BootstrapAdministrator()
    {
        var accounts = _factory.Services.GetRequiredService<IUserAccountService>();
        var challenge = accounts.CreateBootstrapChallenge();
        var result = await accounts.BootstrapAsync(new BootstrapInput
        {
            UserName = "administrator", DisplayName = "Administrator", Password = "Load!Pass2026Load", ConfirmPassword = "Load!Pass2026Load",
            Challenge = challenge.Challenge, TotpCode = SqliteUserAccountService.GenerateTotpCode(challenge.Secret, DateTimeOffset.UtcNow)
        }, default);
        Assert.True(result.Success, result.Message);
    }

    [Fact]
    public async Task ServiceLoad_ConcurrentAcquisitionsAndAnalyses_AreAllConsistent()
    {
        var service = new JsonForensicCaseService(new LoadEnvironment(_root), [new AtlasForense.Forensics.StaticTextAnalyzer()]);
        var cases = new List<ForensicCase>();
        for (var index = 0; index < 5; index++)
        {
            var item = await service.CreateAsync(new CreateCaseInput { Title = $"Load {index}", RequestingOrganization = "Lab", LeadExaminer = "Examiner", Scope = "Load" }, default);
            await service.AuthorizeAsync(new AuthorizeCaseInput { CaseId = item.Id, Authority = "Auth", Reference = $"R{index}", ApprovedBy = "Supervisor" }, default);
            cases.Add(item);
        }

        var jobs = new List<Task<OperationResult>>();
        for (var index = 0; index < 25; index++)
        {
            var item = cases[index % cases.Count];
            var payload = Encoding.UTF8.GetBytes($"carga-{index} https://carga{index}.example.test");
            var file = new FormFile(new MemoryStream(payload), 0, payload.Length, "File", $"load-{index}.txt");
            jobs.Add(service.AcquireAsync(new AcquireEvidenceInput
            {
                CaseId = item.Id, Description = "Load", SourceType = "Test", SourceLocation = "Lab",
                AcquiredBy = "Examiner", AcquisitionMethod = "Load", ToolName = "load", ToolVersion = "1", SourceDeviceIdentifier = $"dev-{index}", File = file
            }, default));
        }
        var results = await Task.WhenAll(jobs);
        Assert.All(results, result => Assert.True(result.Success, result.Message));

        await service.StartAnalysisAsync(cases[0].Id, "Analyst", default);
        var analyses = await Task.WhenAll(cases[0].Evidence.Select(evidence => service.AnalyzeEvidenceAsync(cases[0].Id, evidence.Id, "Analyst", default)));
        Assert.All(analyses, result => Assert.True(result.Success, result.Message));

        var reloaded = new JsonForensicCaseService(new LoadEnvironment(_root), [new AtlasForense.Forensics.StaticTextAnalyzer()]);
        Assert.Equal(5, reloaded.GetAll().Count);
        Assert.Equal(25, reloaded.GetAll().Sum(x => x.Evidence.Count));
        Assert.True((await reloaded.VerifyAsync(default)).Success);
    }

    public void Dispose()
    {
        _factory.Dispose();
        if (Directory.Exists(_root)) Directory.Delete(_root, true);
    }

    private sealed class LoadEnvironment(string root) : IWebHostEnvironment
    {
        public string ApplicationName { get; set; } = "AtlasForense.Tests";
        public IFileProvider WebRootFileProvider { get; set; } = new PhysicalFileProvider(Directory.CreateDirectory(Path.Combine(root, "wwwroot")).FullName);
        public string WebRootPath { get; set; } = Path.Combine(root, "wwwroot");
        public string EnvironmentName { get; set; } = "Testing";
        public string ContentRootPath { get; set; } = root;
        public IFileProvider ContentRootFileProvider { get; set; } = new PhysicalFileProvider(root);
    }
}

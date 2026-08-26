using System.Net;
using System.Text.RegularExpressions;
using AtlasForense.Models;
using AtlasForense.Services;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace AtlasForense.Tests;

public sealed partial class MetricsEndpointTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"atlas-metrics-{Guid.NewGuid():N}");
    private readonly WebApplicationFactory<Program> _factory;

    public MetricsEndpointTests()
    {
        Directory.CreateDirectory(_root);
        _factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Testing").UseContentRoot(_root);
            builder.ConfigureLogging(logging => logging.ClearProviders().AddDebug());
        });
    }

    [Fact]
    public async Task Metrics_RequireAuthentication_AndExposeOperationalJsonForAuditors()
    {
        using var anonymous = CreateClient();
        var denied = await anonymous.GetAsync("/Metrics");
        Assert.Equal(HttpStatusCode.Redirect, denied.StatusCode);
        Assert.StartsWith("/Account/Login", denied.Headers.Location?.PathAndQuery);

        var accounts = _factory.Services.GetRequiredService<IUserAccountService>();
        var challenge = accounts.CreateBootstrapChallenge();
        var bootstrap = await accounts.BootstrapAsync(new BootstrapInput
        {
            UserName = "auditor", DisplayName = "Auditor", Password = "Metrics!Pass2026Aud", ConfirmPassword = "Metrics!Pass2026Aud",
            Challenge = challenge.Challenge, TotpCode = SqliteUserAccountService.GenerateTotpCode(challenge.Secret, DateTimeOffset.UtcNow)
        }, default);
        Assert.True(bootstrap.Success, bootstrap.Message);

        using var client = CreateClient();
        var token = await AntiforgeryTokenAsync(client, "/Account/Login");
        var login = await client.PostAsync("/Account/Login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = token, ["UserName"] = "auditor", ["Password"] = "Metrics!Pass2026Aud",
            ["MfaCode"] = SqliteUserAccountService.GenerateTotpCode(challenge.Secret, DateTimeOffset.UtcNow)
        }));
        Assert.Equal(HttpStatusCode.Redirect, login.StatusCode);

        var response = await client.GetAsync("/Metrics");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("\"cases\"", body);
        Assert.Contains("\"retention\"", body);
        Assert.Contains("\"analysis\"", body);
    }

    private HttpClient CreateClient() => _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = true, BaseAddress = new Uri("https://localhost") });

    private static async Task<string> AntiforgeryTokenAsync(HttpClient client, string path)
    {
        var html = await (await client.GetAsync(path)).Content.ReadAsStringAsync();
        return System.Net.WebUtility.HtmlDecode(Regex.Match(html, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value);
    }

    public void Dispose()
    {
        _factory.Dispose();
        if (Directory.Exists(_root)) Directory.Delete(_root, true);
    }
}

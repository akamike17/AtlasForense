using System.Net;
using AtlasForense.Models;
using AtlasForense.Services;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace AtlasForense.Tests;

// Batería DAST automatizada: sondas black-box sobre la aplicación viva, sin
// conocimiento interno. Sustituye parcialmente (no reemplaza) un escáner externo.
public sealed class DastSecurityProbeTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"atlas-dast-{Guid.NewGuid():N}");
    private readonly WebApplicationFactory<Program> _factory;

    public DastSecurityProbeTests()
    {
        Directory.CreateDirectory(_root);
        _factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Testing").UseContentRoot(_root);
            builder.ConfigureLogging(logging => logging.ClearProviders().AddDebug());
        });
    }

    private HttpClient Client() => _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = true, BaseAddress = new Uri("https://localhost") });

    [Theory]
    [InlineData("/Cases")]
    [InlineData("/Cases/Create")]
    [InlineData("/Users")]
    [InlineData("/Laboratory")]
    public async Task Probe_AnonymousAccessToProtectedRoutes_IsRedirectedOrUnauthorized(string path)
    {
        using var client = Client();

        var navigation = await client.GetAsync(path);
        Assert.Equal(HttpStatusCode.Redirect, navigation.StatusCode);
        Assert.StartsWith("/Account/Login", navigation.Headers.Location?.PathAndQuery);

        using var api = new HttpRequestMessage(HttpMethod.Get, path);
        api.Headers.Accept.ParseAdd("application/json");
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(api)).StatusCode);
    }

    [Fact]
    public async Task Probe_SecurityHeaders_ArePresentOnEveryResponse()
    {
        using var client = Client();
        foreach (var path in new[] { "/Account/Login", "/", "/Account/AccessDenied" })
        {
            var response = await client.GetAsync(path);
            Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
            Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
            Assert.Equal("no-referrer", response.Headers.GetValues("Referrer-Policy").Single());
            var csp = response.Headers.GetValues("Content-Security-Policy").Single();
            Assert.Contains("default-src 'self'", csp);
            Assert.Contains("frame-ancestors 'none'", csp);
            Assert.Contains("script-src 'self'", csp);
            Assert.Contains("camera=()", response.Headers.GetValues("Permissions-Policy").Single());
        }
    }

    [Fact]
    public async Task Probe_MutationsWithoutAntiforgeryToken_AreRejectedWith400()
    {
        using var client = Client();
        foreach (var path in new[] { "/Cases/Create", "/Cases/Authorize", "/Account/Login" })
        {
            var response = await client.PostAsync(path, new FormUrlEncodedContent(new Dictionary<string, string> { ["Title"] = "sonda" }));
            Assert.True(response.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.Redirect,
                $"{path} sin token antiforgery devolvió {(int)response.StatusCode}.");
            if (response.StatusCode == HttpStatusCode.Redirect)
                Assert.StartsWith("/Account/Login", response.Headers.Location?.PathAndQuery);
        }
    }

    [Theory]
    [InlineData("PUT")]
    [InlineData("DELETE")]
    [InlineData("PATCH")]
    public async Task Probe_UnusualHttpMethods_NeverProduceServerError(string method)
    {
        using var client = Client();
        foreach (var path in new[] { "/Cases", "/Account/Login", "/" })
        {
            using var request = new HttpRequestMessage(new HttpMethod(method), path) { Content = new StringContent("sonda") };
            var response = await client.SendAsync(request);
            Assert.True((int)response.StatusCode < 500, $"{method} {path} produjo {(int)response.StatusCode}.");
        }
    }

    [Theory]
    [InlineData("/../appsettings.json")]
    [InlineData("/%2e%2e/appsettings.json")]
    [InlineData("/..%255c..%255cappsettings.json")]
    [InlineData("/Home/..%2fCases")]
    [InlineData("/appsettings.json")]
    public async Task Probe_PathTraversal_NeverDisclosesConfiguration(string path)
    {
        using var client = Client();
        var response = await client.GetAsync(path);
        Assert.True(response.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.BadRequest or HttpStatusCode.Redirect or HttpStatusCode.Unauthorized,
            $"La ruta {path} devolvió {(int)response.StatusCode}.");
        if (response.StatusCode == HttpStatusCode.OK)
            Assert.DoesNotContain("ConnectionStrings", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Probe_RateLimiter_Returns429UnderBurst()
    {
        using var client = Client();
        var statuses = new List<HttpStatusCode>();
        for (var index = 0; index < 140; index++)
            statuses.Add((await client.GetAsync("/Account/Login")).StatusCode);
        Assert.Contains(HttpStatusCode.TooManyRequests, statuses);
    }

    [Fact]
    public async Task Probe_FailedLogin_DoesNotLeakServerErrorsOrStackTraces()
    {
        var accounts = _factory.Services.GetRequiredService<IUserAccountService>();
        if (!accounts.HasUsers())
        {
            var challenge = accounts.CreateBootstrapChallenge();
            await accounts.BootstrapAsync(new BootstrapInput
            {
                UserName = "administrator", DisplayName = "Administrator", Password = "Dast!Pass2026Dast", ConfirmPassword = "Dast!Pass2026Dast",
                Challenge = challenge.Challenge, TotpCode = SqliteUserAccountService.GenerateTotpCode(challenge.Secret, DateTimeOffset.UtcNow)
            }, default);
        }
        using var client = Client();
        var html = await (await client.GetAsync("/Account/Login")).Content.ReadAsStringAsync();
        var token = System.Net.WebUtility.HtmlDecode(System.Text.RegularExpressions.Regex.Match(html, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value);
        var response = await client.PostAsync("/Account/Login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = token, ["UserName"] = "inexistente", ["Password"] = "Sonda!Incorrecta1", ["MfaCode"] = "000000"
        }));
        Assert.NotEqual(HttpStatusCode.InternalServerError, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("StackTrace", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("System.", body);
    }

    [Fact]
    public async Task Probe_HealthEndpoint_IsOperationalForOrchestrators()
    {
        using var client = Client();
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/healthz")).StatusCode);
    }

    public void Dispose()
    {
        _factory.Dispose();
        if (Directory.Exists(_root)) Directory.Delete(_root, true);
    }
}

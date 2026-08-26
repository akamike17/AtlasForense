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

public sealed partial class AuthenticationIntegrationTests : IDisposable
{
    private const string Password = "Integration!Pass2026";
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"atlas-auth-http-{Guid.NewGuid():N}");
    private readonly WebApplicationFactory<Program> _factory;

    public AuthenticationIntegrationTests()
    {
        Directory.CreateDirectory(_root);
        _factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Testing").UseContentRoot(_root);
            builder.ConfigureLogging(logging => logging.ClearProviders().AddDebug());
        });
    }

    [Fact]
    public async Task NavigationRedirectsToLoginWhileJsonRequestGets401()
    {
        using var client = CreateClient(false);

        var navigation = await client.GetAsync("/Cases");
        using var jsonRequest = new HttpRequestMessage(HttpMethod.Get, "/Cases");
        jsonRequest.Headers.Accept.ParseAdd("application/json");
        var api = await client.SendAsync(jsonRequest);

        Assert.Equal(HttpStatusCode.Redirect, navigation.StatusCode);
        Assert.StartsWith("/Account/Login", navigation.Headers.Location?.PathAndQuery);
        Assert.Equal(HttpStatusCode.Unauthorized, api.StatusCode);
        Assert.Null(api.Headers.Location);
    }

    [Fact]
    public async Task LoginRequiresAntiforgeryAndRejectsExternalReturnUrl()
    {
        var (secret, _) = await BootstrapAdministrator();
        using var client = CreateClient(false);
        var missingToken = await client.PostAsync("/Account/Login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["UserName"] = "administrator", ["Password"] = Password, ["MfaCode"] = SqliteUserAccountService.GenerateTotpCode(secret, DateTimeOffset.UtcNow)
        }));
        Assert.Equal(HttpStatusCode.BadRequest, missingToken.StatusCode);

        var loginPage = await client.GetAsync("/Account/Login?returnUrl=https%3A%2F%2Fevil.example%2Fsteal");
        var html = await loginPage.Content.ReadAsStringAsync();
        var token = TokenRegex().Match(html).Groups[1].Value;
        var response = await client.PostAsync("/Account/Login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = WebUtility.HtmlDecode(token), ["UserName"] = "administrator", ["Password"] = Password,
            ["MfaCode"] = SqliteUserAccountService.GenerateTotpCode(secret, DateTimeOffset.UtcNow), ["ReturnUrl"] = "https://evil.example/steal"
        }));

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/Cases", response.Headers.Location?.OriginalString);
        var cookie = Assert.Single(response.Headers.GetValues("Set-Cookie"), value => value.StartsWith("__Host-AtlasForense=", StringComparison.Ordinal) && !value.StartsWith("__Host-AtlasForense=;", StringComparison.Ordinal));
        Assert.Contains("secure", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("httponly", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=strict", cookie, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task CaseAuthorizationMatrix_BlocksUnassignedAndWrongRoleOperations()
    {
        var accounts = _factory.Services.GetRequiredService<IUserAccountService>();
        var (adminSecret, _) = await BootstrapAdministrator();
        var administrator = accounts.GetAll().Single();
        var examiner = await accounts.CreateUserAsync(administrator.Id, new CreateUserInput { UserName = "examiner", DisplayName = "Examiner", TemporaryPassword = "Temporary!Exam2026", Role = ForensicRole.Examiner }, default);
        var reviewer = await accounts.CreateUserAsync(administrator.Id, new CreateUserInput { UserName = "reviewer", DisplayName = "Reviewer", TemporaryPassword = "Temporary!Review2026", Role = ForensicRole.Reviewer }, default);
        var auditor = await accounts.CreateUserAsync(administrator.Id, new CreateUserInput { UserName = "auditor", DisplayName = "Auditor", TemporaryPassword = "Temporary!Audit2026", Role = ForensicRole.Auditor }, default);
        await ChangeProvisionedPassword(accounts, examiner, "Temporary!Exam2026", "Permanent!Exam2026");
        await ChangeProvisionedPassword(accounts, reviewer, "Temporary!Review2026", "Permanent!Review2026");
        await ChangeProvisionedPassword(accounts, auditor, "Temporary!Audit2026", "Permanent!Audit2026");
        var cases = _factory.Services.GetRequiredService<IForensicCaseService>();
        var item = await cases.CreateAsync(new CreateCaseInput { Title = "Restricted", RequestingOrganization = "Lab", LeadExaminer = "Examiner", Scope = "Authorization", ActorUserId = examiner.User!.Id }, default);
        await cases.AssignUserAsync(new CaseAssignmentInput { CaseId = item.Id, UserId = reviewer.User!.Id, Role = ForensicRole.Reviewer }, administrator.Id, administrator.DisplayName, default);

        using var examinerClient = CreateClient(false);
        using var reviewerClient = CreateClient(false);
        using var auditorClient = CreateClient(false);
        await LoginAsync(examinerClient, "examiner", "Permanent!Exam2026", examiner.TotpSecret);
        await LoginAsync(reviewerClient, "reviewer", "Permanent!Review2026", reviewer.TotpSecret);
        await LoginAsync(auditorClient, "auditor", "Permanent!Audit2026", auditor.TotpSecret);

        Assert.Equal(HttpStatusCode.OK, (await examinerClient.GetAsync($"/Cases/Details/{item.Id}")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await reviewerClient.GetAsync($"/Cases/Details/{item.Id}")).StatusCode);
        var deniedNavigation = await auditorClient.GetAsync($"/Cases/Details/{item.Id}");
        Assert.Equal(HttpStatusCode.Redirect, deniedNavigation.StatusCode);
        Assert.StartsWith("/Account/AccessDenied", deniedNavigation.Headers.Location?.PathAndQuery);
        using var deniedApiRequest = new HttpRequestMessage(HttpMethod.Get, $"/Cases/Details/{item.Id}");
        deniedApiRequest.Headers.Accept.ParseAdd("application/json");
        Assert.Equal(HttpStatusCode.Forbidden, (await auditorClient.SendAsync(deniedApiRequest)).StatusCode);
        var token = await AntiforgeryTokenAsync(reviewerClient, $"/Cases/Details/{item.Id}");
        var forbiddenMutation = await reviewerClient.PostAsync("/Cases/StartAnalysis", new FormUrlEncodedContent(new Dictionary<string, string> { ["__RequestVerificationToken"] = token, ["id"] = item.Id.ToString("D") }));
        Assert.Equal(HttpStatusCode.Redirect, forbiddenMutation.StatusCode);
        Assert.StartsWith("/Account/AccessDenied", forbiddenMutation.Headers.Location?.PathAndQuery);
        _ = adminSecret;
    }

    private async Task<(string Secret, IReadOnlyList<string> RecoveryCodes)> BootstrapAdministrator()
    {
        var accounts = _factory.Services.GetRequiredService<IUserAccountService>();
        var challenge = accounts.CreateBootstrapChallenge();
        var result = await accounts.BootstrapAsync(new BootstrapInput
        {
            UserName = "administrator", DisplayName = "Administrator", Password = Password, ConfirmPassword = Password,
            Challenge = challenge.Challenge, TotpCode = SqliteUserAccountService.GenerateTotpCode(challenge.Secret, DateTimeOffset.UtcNow)
        }, default);
        Assert.True(result.Success, result.Message);
        return (challenge.Secret, result.RecoveryCodes);
    }

    private HttpClient CreateClient(bool redirects) => _factory.CreateClient(new WebApplicationFactoryClientOptions
    {
        AllowAutoRedirect = redirects, HandleCookies = true, BaseAddress = new Uri("https://localhost")
    });

    private static async Task LoginAsync(HttpClient client, string userName, string password, string secret)
    {
        var token = await AntiforgeryTokenAsync(client, "/Account/Login");
        var response = await client.PostAsync("/Account/Login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = token, ["UserName"] = userName, ["Password"] = password,
            ["MfaCode"] = SqliteUserAccountService.GenerateTotpCode(secret, DateTimeOffset.UtcNow)
        }));
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
    }

    private static async Task<string> AntiforgeryTokenAsync(HttpClient client, string path)
    {
        var html = await (await client.GetAsync(path)).Content.ReadAsStringAsync();
        return WebUtility.HtmlDecode(TokenRegex().Match(html).Groups[1].Value);
    }

    private static async Task ChangeProvisionedPassword(IUserAccountService accounts, UserProvisioningResult user, string temporary, string permanent)
    {
        var result = await accounts.ChangePasswordAsync(user.User!.Id, new ChangePasswordInput
        {
            CurrentPassword = temporary, MfaCode = SqliteUserAccountService.GenerateTotpCode(user.TotpSecret, DateTimeOffset.UtcNow),
            NewPassword = permanent, ConfirmPassword = permanent
        }, default);
        Assert.True(result.Success, result.Message);
    }

    public void Dispose()
    {
        _factory.Dispose();
        if (Directory.Exists(_root)) Directory.Delete(_root, true);
    }

    [GeneratedRegex("name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"")]
    private static partial Regex TokenRegex();
}

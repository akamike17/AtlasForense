using AtlasForense.Models;
using AtlasForense.Services;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.FileProviders;
using Xunit;

namespace AtlasForense.Tests;

public sealed class UserAccountServiceTests : IDisposable
{
    private const string StrongPassword = "Forensic!Pass2026";
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"atlas-identity-{Guid.NewGuid():N}");
    private readonly SqliteUserAccountService _service;

    public UserAccountServiceTests()
    {
        Directory.CreateDirectory(_root);
        var protection = DataProtectionProvider.Create(new DirectoryInfo(Path.Combine(_root, "keys")), configuration => configuration.SetApplicationName("AtlasForense.Tests"));
        _service = new SqliteUserAccountService(new TestEnvironment(_root), protection);
    }

    [Fact]
    public async Task Bootstrap_CreatesSingleAdministratorWithTotpAndProtectedSecrets()
    {
        var (input, secret) = CreateBootstrapInput();

        var result = await _service.BootstrapAsync(input, default);

        Assert.True(result.Success, result.Message);
        Assert.Equal(ForensicRole.Administrator, result.User!.Role);
        Assert.Equal(10, result.RecoveryCodes.Count);
        Assert.True(_service.HasUsers());
        var databaseFiles = Directory.GetFiles(Path.Combine(_root, "App_Data"), "atlas-forense.db*");
        var databaseText = string.Concat(databaseFiles.Select(path => System.Text.Encoding.UTF8.GetString(File.ReadAllBytes(path))));
        Assert.DoesNotContain(StrongPassword, databaseText, StringComparison.Ordinal);
        Assert.DoesNotContain(secret, databaseText, StringComparison.Ordinal);
        Assert.Contains("INITIAL_ADMIN_CREATED", databaseText, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Bootstrap_RejectsWeakPasswordAndSecondAdministratorRace()
    {
        var (weak, _) = CreateBootstrapInput();
        weak.Password = weak.ConfirmPassword = "short";
        Assert.False((await _service.BootstrapAsync(weak, default)).Success);

        var attempts = Enumerable.Range(0, 2).Select(_ =>
        {
            var (input, _) = CreateBootstrapInput();
            return _service.BootstrapAsync(input, default);
        });
        var results = await Task.WhenAll(attempts);

        Assert.Single(results, result => result.Success);
        Assert.Single(results, result => !result.Success);
    }

    [Fact]
    public async Task Authentication_RequiresMfaAndConsumesRecoveryCodeOnce()
    {
        var (input, _) = CreateBootstrapInput();
        var bootstrap = await _service.BootstrapAsync(input, default);

        var missingMfa = await _service.AuthenticateAsync(input.UserName, StrongPassword, string.Empty, default);
        var code = bootstrap.RecoveryCodes[0];
        var recovered = await _service.AuthenticateAsync(input.UserName, StrongPassword, code, default);
        var replay = await _service.AuthenticateAsync(input.UserName, StrongPassword, code, default);

        Assert.True(missingMfa.RequiresMfa);
        Assert.True(recovered.Success);
        Assert.True(recovered.UsedRecoveryCode);
        Assert.False(replay.Success);
    }

    [Fact]
    public async Task Authentication_LocksAccountAfterRepeatedFailures()
    {
        var (input, _) = CreateBootstrapInput();
        await _service.BootstrapAsync(input, default);
        for (var attempt = 0; attempt < 5; attempt++)
            await _service.AuthenticateAsync(input.UserName, "Wrong!Password000", "000000", default);

        var result = await _service.AuthenticateAsync(input.UserName, StrongPassword, "000000", default);

        Assert.False(result.Success);
        Assert.Contains("bloqueada", result.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task SessionRevocation_ChangesSecurityStamp()
    {
        var (input, _) = CreateBootstrapInput();
        var created = await _service.BootstrapAsync(input, default);
        var before = created.User!.SecurityStamp;

        await _service.RevokeSessionsAsync(created.User.Id, default);

        Assert.NotEqual(before, _service.GetById(created.User.Id)!.SecurityStamp);
    }

    [Fact]
    public async Task Administrator_CreatesEveryOperationalRoleAndCanDisableAccounts()
    {
        var (bootstrapInput, _) = CreateBootstrapInput();
        var administrator = (await _service.BootstrapAsync(bootstrapInput, default)).User!;
        foreach (var role in Enum.GetValues<ForensicRole>().Where(role => role != ForensicRole.Administrator))
        {
            var result = await _service.CreateUserAsync(administrator.Id, new CreateUserInput
            {
                UserName = role.ToString().ToLowerInvariant(), DisplayName = role.ToString(), TemporaryPassword = $"Temporary!{role}2026", Role = role
            }, default);
            Assert.True(result.Success, result.Message);
            Assert.Equal(role, result.User!.Role);
            Assert.True(result.User.MustChangePassword);
            Assert.Equal(10, result.RecoveryCodes.Count);
        }
        var examiner = _service.GetAll().Single(x => x.Role == ForensicRole.Examiner);
        Assert.True(await _service.SetEnabledAsync(administrator.Id, examiner.Id, false, default));
        Assert.False(_service.GetById(examiner.Id)!.Enabled);
        Assert.False(await _service.SetEnabledAsync(administrator.Id, administrator.Id, false, default));
    }

    [Fact]
    public async Task ForcedPasswordChange_ReauthenticatesAndRevokesPreviousPassword()
    {
        var (bootstrapInput, _) = CreateBootstrapInput();
        var administrator = (await _service.BootstrapAsync(bootstrapInput, default)).User!;
        var provisioned = await _service.CreateUserAsync(administrator.Id, new CreateUserInput
        {
            UserName = "examiner", DisplayName = "Examiner", TemporaryPassword = "Temporary!Exam2026", Role = ForensicRole.Examiner
        }, default);
        var newPassword = "Permanent!Exam2026";
        var changed = await _service.ChangePasswordAsync(provisioned.User!.Id, new ChangePasswordInput
        {
            CurrentPassword = "Temporary!Exam2026", MfaCode = SqliteUserAccountService.GenerateTotpCode(provisioned.TotpSecret, DateTimeOffset.UtcNow),
            NewPassword = newPassword, ConfirmPassword = newPassword
        }, default);

        Assert.True(changed.Success, changed.Message);
        Assert.False(_service.GetById(provisioned.User.Id)!.MustChangePassword);
        Assert.False((await _service.AuthenticateAsync("examiner", "Temporary!Exam2026", "000000", default)).Success);
        Assert.True((await _service.AuthenticateAsync("examiner", newPassword, SqliteUserAccountService.GenerateTotpCode(provisioned.TotpSecret, DateTimeOffset.UtcNow), default)).Success);
    }

    private (BootstrapInput Input, string Secret) CreateBootstrapInput()
    {
        var challenge = _service.CreateBootstrapChallenge();
        return (new BootstrapInput
        {
            UserName = "administrator", DisplayName = "Forensic Administrator", Password = StrongPassword,
            ConfirmPassword = StrongPassword, Challenge = challenge.Challenge,
            TotpCode = SqliteUserAccountService.GenerateTotpCode(challenge.Secret, DateTimeOffset.UtcNow)
        }, challenge.Secret);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root)) Directory.Delete(_root, true);
    }

    private sealed class TestEnvironment : IWebHostEnvironment
    {
        public TestEnvironment(string root)
        {
            ContentRootPath = root; WebRootPath = Path.Combine(root, "wwwroot"); Directory.CreateDirectory(WebRootPath);
            ContentRootFileProvider = new PhysicalFileProvider(root); WebRootFileProvider = new PhysicalFileProvider(WebRootPath);
        }
        public string ApplicationName { get; set; } = "AtlasForense.Tests";
        public IFileProvider WebRootFileProvider { get; set; }
        public string WebRootPath { get; set; }
        public string EnvironmentName { get; set; } = "Testing";
        public string ContentRootPath { get; set; }
        public IFileProvider ContentRootFileProvider { get; set; }
    }
}

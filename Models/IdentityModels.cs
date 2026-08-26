using System.ComponentModel.DataAnnotations;

namespace AtlasForense.Models;

public enum ForensicRole { Administrator, Examiner, Reviewer, Custodian, Auditor }

public sealed class AppUser
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string UserName { get; set; } = string.Empty;
    public string NormalizedUserName { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public ForensicRole Role { get; set; }
    public bool Enabled { get; set; } = true;
    public bool MustChangePassword { get; set; }
    public string ProtectedTotpSecret { get; set; } = string.Empty;
    public string RecoveryCodeHashesJson { get; set; } = "[]";
    public int FailedAccessCount { get; set; }
    public DateTimeOffset? LockoutEndUtc { get; set; }
    public string SecurityStamp { get; set; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
}

public sealed class BootstrapInput
{
    [Required, StringLength(80, MinimumLength = 3)] public string UserName { get; set; } = string.Empty;
    [Required, StringLength(120, MinimumLength = 2)] public string DisplayName { get; set; } = string.Empty;
    [Required, StringLength(256, MinimumLength = 14)] public string Password { get; set; } = string.Empty;
    [Required, Compare(nameof(Password))] public string ConfirmPassword { get; set; } = string.Empty;
    [Required] public string Challenge { get; set; } = string.Empty;
    [Required, RegularExpression("^[0-9]{6}$")] public string TotpCode { get; set; } = string.Empty;
}

public sealed class LoginInput
{
    [Required] public string UserName { get; set; } = string.Empty;
    [Required] public string Password { get; set; } = string.Empty;
    [StringLength(32)] public string MfaCode { get; set; } = string.Empty;
    public string ReturnUrl { get; set; } = string.Empty;
}

public sealed class CreateUserInput
{
    [Required, StringLength(80, MinimumLength = 3)] public string UserName { get; set; } = string.Empty;
    [Required, StringLength(120, MinimumLength = 2)] public string DisplayName { get; set; } = string.Empty;
    [Required, StringLength(256, MinimumLength = 14)] public string TemporaryPassword { get; set; } = string.Empty;
    public ForensicRole Role { get; set; }
}

public sealed class ChangePasswordInput
{
    [Required] public string CurrentPassword { get; set; } = string.Empty;
    [Required] public string MfaCode { get; set; } = string.Empty;
    [Required, StringLength(256, MinimumLength = 14)] public string NewPassword { get; set; } = string.Empty;
    [Required, Compare(nameof(NewPassword))] public string ConfirmPassword { get; set; } = string.Empty;
}

public sealed record BootstrapChallenge(string Secret, string Challenge, DateTimeOffset ExpiresAtUtc);
public sealed class BootstrapViewModel
{
    public BootstrapInput Input { get; set; } = new();
    public string Secret { get; set; } = string.Empty;
    public DateTimeOffset ExpiresAtUtc { get; set; }
}
public sealed record BootstrapResult(bool Success, string Message, AppUser? User, IReadOnlyList<string> RecoveryCodes);
public sealed record UserProvisioningResult(bool Success, string Message, AppUser? User, string TotpSecret, IReadOnlyList<string> RecoveryCodes);
public sealed record AuthenticationResult(bool Success, string Message, AppUser? User, bool RequiresMfa, bool UsedRecoveryCode);

using AtlasForense.Models;

namespace AtlasForense.Services;

public interface IUserAccountService
{
    bool HasUsers();
    BootstrapChallenge CreateBootstrapChallenge();
    Task<BootstrapResult> BootstrapAsync(BootstrapInput input, CancellationToken cancellationToken);
    Task<AuthenticationResult> AuthenticateAsync(string userName, string password, string mfaCode, CancellationToken cancellationToken);
    AppUser? GetById(Guid id);
    IReadOnlyList<AppUser> GetAll();
    Task<UserProvisioningResult> CreateUserAsync(Guid administratorId, CreateUserInput input, CancellationToken cancellationToken);
    Task<bool> SetEnabledAsync(Guid administratorId, Guid userId, bool enabled, CancellationToken cancellationToken);
    Task<OperationResult> ChangePasswordAsync(Guid userId, ChangePasswordInput input, CancellationToken cancellationToken);
    Task RevokeSessionsAsync(Guid id, CancellationToken cancellationToken);
}

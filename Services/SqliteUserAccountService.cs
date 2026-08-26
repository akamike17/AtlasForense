using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AtlasForense.Models;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;

namespace AtlasForense.Services;

public sealed class SqliteUserAccountService : IUserAccountService
{
    private const int MaxFailedAccess = 5;
    private static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);
    private readonly string _databasePath;
    private readonly IDataProtector _totpProtector;
    private readonly ITimeLimitedDataProtector _challengeProtector;
    private readonly PasswordHasher<AppUser> _passwordHasher = new();
    private readonly SemaphoreSlim _gate = new(1, 1);

    static SqliteUserAccountService() => SqliteRuntime.Initialize();

    public SqliteUserAccountService(IWebHostEnvironment environment, IDataProtectionProvider protectionProvider)
    {
        var dataPath = Path.Combine(environment.ContentRootPath, "App_Data");
        Directory.CreateDirectory(dataPath);
        _databasePath = Path.Combine(dataPath, "atlas-forense.db");
        _totpProtector = protectionProvider.CreateProtector("AtlasForense.Identity.Totp.v1");
        _challengeProtector = protectionProvider.CreateProtector("AtlasForense.Identity.Bootstrap.v1").ToTimeLimitedDataProtector();
        InitializeDatabase();
    }

    public bool HasUsers()
    {
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT EXISTS(SELECT 1 FROM Users LIMIT 1);";
        return Convert.ToInt32(command.ExecuteScalar(), CultureInfo.InvariantCulture) == 1;
    }

    public BootstrapChallenge CreateBootstrapChallenge()
    {
        var secret = Base32Encode(RandomNumberGenerator.GetBytes(20));
        var expires = DateTimeOffset.UtcNow.AddMinutes(10);
        var payload = JsonSerializer.Serialize(new ChallengePayload(secret, expires));
        return new(secret, _challengeProtector.Protect(payload, TimeSpan.FromMinutes(10)), expires);
    }

    public async Task<BootstrapResult> BootstrapAsync(BootstrapInput input, CancellationToken cancellationToken)
    {
        if (!PasswordIsStrong(input.Password, out var policyError)) return new(false, policyError, null, []);
        ChallengePayload challenge;
        try
        {
            challenge = JsonSerializer.Deserialize<ChallengePayload>(_challengeProtector.Unprotect(input.Challenge))
                ?? throw new CryptographicException();
        }
        catch (CryptographicException) { return new(false, "El desafío de configuración expiró o no es válido.", null, []); }
        if (challenge.ExpiresAtUtc < DateTimeOffset.UtcNow || !VerifyTotp(challenge.Secret, input.TotpCode, DateTimeOffset.UtcNow))
            return new(false, "El código TOTP no es válido.", null, []);

        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var connection = OpenConnection();
            await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
            await using var count = connection.CreateCommand();
            count.Transaction = transaction;
            count.CommandText = "SELECT COUNT(*) FROM Users;";
            if (Convert.ToInt64(await count.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture) != 0)
                return new(false, "La configuración inicial ya fue completada.", null, []);

            var user = new AppUser
            {
                UserName = input.UserName.Trim(), NormalizedUserName = Normalize(input.UserName), DisplayName = input.DisplayName.Trim(),
                Role = ForensicRole.Administrator, ProtectedTotpSecret = _totpProtector.Protect(challenge.Secret)
            };
            user.PasswordHash = _passwordHasher.HashPassword(user, input.Password);
            var recoveryCodes = GenerateRecoveryCodes();
            user.RecoveryCodeHashesJson = JsonSerializer.Serialize(recoveryCodes.Select(HashRecoveryCode));
            await InsertUserAsync(connection, transaction, user, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            await WriteSecurityEventAsync(user.Id, "INITIAL_ADMIN_CREATED", true, "Configuración inicial completada.", cancellationToken);
            return new(true, "Cuenta administradora creada con MFA.", user, recoveryCodes);
        }
        catch (SqliteException exception) when (exception.SqliteErrorCode == 19)
        {
            return new(false, "El nombre de usuario ya existe.", null, []);
        }
        finally { _gate.Release(); }
    }

    public async Task<AuthenticationResult> AuthenticateAsync(string userName, string password, string mfaCode, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var user = FindByNormalizedName(Normalize(userName));
            if (user is null) { await WriteSecurityEventAsync(null, "LOGIN_FAILED", false, "Cuenta no reconocida.", cancellationToken); return Failure(); }
            if (!user.Enabled) { await WriteSecurityEventAsync(user.Id, "LOGIN_FAILED", false, "Cuenta deshabilitada.", cancellationToken); return Failure(); }
            if (user.LockoutEndUtc > DateTimeOffset.UtcNow) { await WriteSecurityEventAsync(user.Id, "LOGIN_BLOCKED", false, "Bloqueo temporal activo.", cancellationToken); return new(false, "La cuenta está temporalmente bloqueada.", null, false, false); }
            var passwordResult = _passwordHasher.VerifyHashedPassword(user, user.PasswordHash, password);
            if (passwordResult == PasswordVerificationResult.Failed)
            {
                await RecordFailureAsync(user, cancellationToken);
                await WriteSecurityEventAsync(user.Id, "LOGIN_FAILED", false, "Factor de contraseña no válido.", cancellationToken);
                return Failure();
            }
            if (string.IsNullOrWhiteSpace(mfaCode)) { await WriteSecurityEventAsync(user.Id, "MFA_REQUIRED", false, "Segundo factor ausente.", cancellationToken); return new(false, "Se requiere el código MFA.", null, true, false); }
            var secret = _totpProtector.Unprotect(user.ProtectedTotpSecret);
            var usedRecovery = false;
            if (!VerifyTotp(secret, mfaCode, DateTimeOffset.UtcNow))
            {
                var hashes = JsonSerializer.Deserialize<List<string>>(user.RecoveryCodeHashesJson) ?? [];
                var candidate = HashRecoveryCode(mfaCode);
                var index = hashes.FindIndex(hash => CryptographicOperations.FixedTimeEquals(Convert.FromHexString(hash), Convert.FromHexString(candidate)));
                if (index < 0)
                {
                    await RecordFailureAsync(user, cancellationToken);
                    await WriteSecurityEventAsync(user.Id, "LOGIN_FAILED", false, "Segundo factor no válido.", cancellationToken);
                    return Failure();
                }
                hashes.RemoveAt(index);
                user.RecoveryCodeHashesJson = JsonSerializer.Serialize(hashes);
                usedRecovery = true;
            }
            user.FailedAccessCount = 0;
            user.LockoutEndUtc = null;
            if (passwordResult == PasswordVerificationResult.SuccessRehashNeeded) user.PasswordHash = _passwordHasher.HashPassword(user, password);
            await UpdateUserAsync(user, cancellationToken);
            await WriteSecurityEventAsync(user.Id, usedRecovery ? "RECOVERY_CODE_USED" : "LOGIN_SUCCEEDED", true, usedRecovery ? "Código de recuperación consumido." : "MFA verificado.", cancellationToken);
            return new(true, "Autenticación correcta.", user, false, usedRecovery);
        }
        finally { _gate.Release(); }
    }

    public AppUser? GetById(Guid id)
    {
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT Id, UserName, NormalizedUserName, DisplayName, PasswordHash, Role, Enabled, MustChangePassword, ProtectedTotpSecret, RecoveryCodeHashesJson, FailedAccessCount, LockoutEndUtc, SecurityStamp, CreatedAtUtc FROM Users WHERE Id=$id;";
        command.Parameters.AddWithValue("$id", id.ToString("D"));
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadUser(reader) : null;
    }

    public IReadOnlyList<AppUser> GetAll()
    {
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT Id, UserName, NormalizedUserName, DisplayName, PasswordHash, Role, Enabled, MustChangePassword, ProtectedTotpSecret, RecoveryCodeHashesJson, FailedAccessCount, LockoutEndUtc, SecurityStamp, CreatedAtUtc FROM Users ORDER BY DisplayName;";
        using var reader = command.ExecuteReader();
        var users = new List<AppUser>();
        while (reader.Read()) users.Add(ReadUser(reader));
        return users;
    }

    public async Task<UserProvisioningResult> CreateUserAsync(Guid administratorId, CreateUserInput input, CancellationToken cancellationToken)
    {
        var administrator = GetById(administratorId);
        if (administrator is null || !administrator.Enabled || administrator.Role != ForensicRole.Administrator)
            return new(false, "No autorizado.", null, string.Empty, []);
        if (!PasswordIsStrong(input.TemporaryPassword, out var error)) return new(false, error, null, string.Empty, []);
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var secret = Base32Encode(RandomNumberGenerator.GetBytes(20));
            var recoveryCodes = GenerateRecoveryCodes();
            var user = new AppUser
            {
                UserName = input.UserName.Trim(), NormalizedUserName = Normalize(input.UserName), DisplayName = input.DisplayName.Trim(), Role = input.Role,
                MustChangePassword = true, ProtectedTotpSecret = _totpProtector.Protect(secret), RecoveryCodeHashesJson = JsonSerializer.Serialize(recoveryCodes.Select(HashRecoveryCode))
            };
            user.PasswordHash = _passwordHasher.HashPassword(user, input.TemporaryPassword);
            await using var connection = OpenConnection();
            await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
            await InsertUserAsync(connection, transaction, user, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            await WriteSecurityEventAsync(administratorId, "USER_CREATED", true, $"Usuario {user.Id:D}; rol {user.Role}.", cancellationToken);
            return new(true, "Usuario creado; entregue el secreto MFA y la contraseña temporal por canales separados.", user, secret, recoveryCodes);
        }
        catch (SqliteException exception) when (exception.SqliteErrorCode == 19) { return new(false, "El nombre de usuario ya existe.", null, string.Empty, []); }
        finally { _gate.Release(); }
    }

    public async Task<bool> SetEnabledAsync(Guid administratorId, Guid userId, bool enabled, CancellationToken cancellationToken)
    {
        var administrator = GetById(administratorId);
        if (administrator is null || administrator.Role != ForensicRole.Administrator || administratorId == userId) return false;
        await using var connection = OpenConnection();
        await using var command = connection.CreateCommand();
        command.CommandText = "UPDATE Users SET Enabled=$enabled, SecurityStamp=$stamp WHERE Id=$id;";
        command.Parameters.AddWithValue("$enabled", enabled); command.Parameters.AddWithValue("$stamp", Guid.NewGuid().ToString("N")); command.Parameters.AddWithValue("$id", userId.ToString("D"));
        var changed = await command.ExecuteNonQueryAsync(cancellationToken) == 1;
        if (changed) await WriteSecurityEventAsync(administratorId, enabled ? "USER_ENABLED" : "USER_DISABLED", true, $"Usuario {userId:D}.", cancellationToken);
        return changed;
    }

    public async Task<OperationResult> ChangePasswordAsync(Guid userId, ChangePasswordInput input, CancellationToken cancellationToken)
    {
        var user = GetById(userId);
        if (user is null) return OperationResult.Fail("Cuenta no encontrada.");
        var authenticated = await AuthenticateAsync(user.UserName, input.CurrentPassword, input.MfaCode, cancellationToken);
        if (!authenticated.Success) return OperationResult.Fail("La reautenticación falló.");
        if (!PasswordIsStrong(input.NewPassword, out var error)) return OperationResult.Fail(error);
        user = GetById(userId)!;
        user.PasswordHash = _passwordHasher.HashPassword(user, input.NewPassword);
        user.SecurityStamp = Guid.NewGuid().ToString("N");
        await using var connection = OpenConnection();
        await using var command = connection.CreateCommand();
        command.CommandText = "UPDATE Users SET PasswordHash=$password, MustChangePassword=0, SecurityStamp=$stamp WHERE Id=$id;";
        command.Parameters.AddWithValue("$password", user.PasswordHash); command.Parameters.AddWithValue("$stamp", user.SecurityStamp); command.Parameters.AddWithValue("$id", user.Id.ToString("D"));
        await command.ExecuteNonQueryAsync(cancellationToken);
        await WriteSecurityEventAsync(userId, "PASSWORD_CHANGED", true, "Contraseña cambiada y sesiones revocadas.", cancellationToken);
        return OperationResult.Ok("Contraseña cambiada; las sesiones anteriores fueron revocadas.");
    }

    public async Task RevokeSessionsAsync(Guid id, CancellationToken cancellationToken)
    {
        await using var connection = OpenConnection();
        await using var command = connection.CreateCommand();
        command.CommandText = "UPDATE Users SET SecurityStamp=$stamp WHERE Id=$id;";
        command.Parameters.AddWithValue("$stamp", Guid.NewGuid().ToString("N"));
        command.Parameters.AddWithValue("$id", id.ToString("D"));
        await command.ExecuteNonQueryAsync(cancellationToken);
        await WriteSecurityEventAsync(id, "SESSIONS_REVOKED", true, "Sello de seguridad renovado.", cancellationToken);
    }

    private void InitializeDatabase()
    {
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS SchemaMigrations (Version INTEGER NOT NULL PRIMARY KEY, AppliedAtUtc TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS Users (
                Id TEXT NOT NULL PRIMARY KEY, UserName TEXT NOT NULL, NormalizedUserName TEXT NOT NULL UNIQUE,
                DisplayName TEXT NOT NULL, PasswordHash TEXT NOT NULL, Role INTEGER NOT NULL,
                Enabled INTEGER NOT NULL CHECK (Enabled IN (0,1)), MustChangePassword INTEGER NOT NULL CHECK (MustChangePassword IN (0,1)),
                ProtectedTotpSecret TEXT NOT NULL, RecoveryCodeHashesJson TEXT NOT NULL,
                FailedAccessCount INTEGER NOT NULL CHECK (FailedAccessCount >= 0), LockoutEndUtc TEXT NULL,
                SecurityStamp TEXT NOT NULL, CreatedAtUtc TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS SecurityEvents (
                Id TEXT NOT NULL PRIMARY KEY, OccurredAtUtc TEXT NOT NULL, UserId TEXT NULL,
                EventType TEXT NOT NULL, Success INTEGER NOT NULL CHECK (Success IN (0,1)), Detail TEXT NOT NULL
            );
            INSERT OR IGNORE INTO SchemaMigrations (Version, AppliedAtUtc) VALUES (2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
            INSERT OR IGNORE INTO SchemaMigrations (Version, AppliedAtUtc) VALUES (3, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
            """;
        command.ExecuteNonQuery();
    }

    private SqliteConnection OpenConnection()
    {
        var connection = new SqliteConnection($"Data Source={_databasePath};Mode=ReadWriteCreate;Pooling=False");
        connection.Open();
        using var pragma = connection.CreateCommand();
        pragma.CommandText = "PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;";
        pragma.ExecuteNonQuery();
        return connection;
    }

    private AppUser? FindByNormalizedName(string normalized)
    {
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT Id, UserName, NormalizedUserName, DisplayName, PasswordHash, Role, Enabled, MustChangePassword, ProtectedTotpSecret, RecoveryCodeHashesJson, FailedAccessCount, LockoutEndUtc, SecurityStamp, CreatedAtUtc FROM Users WHERE NormalizedUserName=$name;";
        command.Parameters.AddWithValue("$name", normalized);
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadUser(reader) : null;
    }

    private async Task RecordFailureAsync(AppUser user, CancellationToken token)
    {
        user.FailedAccessCount++;
        if (user.FailedAccessCount >= MaxFailedAccess) { user.LockoutEndUtc = DateTimeOffset.UtcNow.Add(LockoutDuration); user.FailedAccessCount = 0; }
        await UpdateUserAsync(user, token);
    }

    private async Task UpdateUserAsync(AppUser user, CancellationToken token)
    {
        await using var connection = OpenConnection();
        await using var command = connection.CreateCommand();
        command.CommandText = "UPDATE Users SET PasswordHash=$password, RecoveryCodeHashesJson=$recovery, FailedAccessCount=$failed, LockoutEndUtc=$lockout, SecurityStamp=$stamp WHERE Id=$id;";
        command.Parameters.AddWithValue("$password", user.PasswordHash);
        command.Parameters.AddWithValue("$recovery", user.RecoveryCodeHashesJson);
        command.Parameters.AddWithValue("$failed", user.FailedAccessCount);
        command.Parameters.AddWithValue("$lockout", (object?)user.LockoutEndUtc?.ToUniversalTime().ToString("O") ?? DBNull.Value);
        command.Parameters.AddWithValue("$stamp", user.SecurityStamp);
        command.Parameters.AddWithValue("$id", user.Id.ToString("D"));
        await command.ExecuteNonQueryAsync(token);
    }

    private async Task WriteSecurityEventAsync(Guid? userId, string eventType, bool success, string detail, CancellationToken token)
    {
        await using var connection = OpenConnection();
        await using var command = connection.CreateCommand();
        command.CommandText = "INSERT INTO SecurityEvents (Id, OccurredAtUtc, UserId, EventType, Success, Detail) VALUES ($id,$occurred,$user,$type,$success,$detail);";
        command.Parameters.AddWithValue("$id", Guid.NewGuid().ToString("D"));
        command.Parameters.AddWithValue("$occurred", DateTimeOffset.UtcNow.ToString("O"));
        command.Parameters.AddWithValue("$user", (object?)userId?.ToString("D") ?? DBNull.Value);
        command.Parameters.AddWithValue("$type", eventType); command.Parameters.AddWithValue("$success", success); command.Parameters.AddWithValue("$detail", detail);
        await command.ExecuteNonQueryAsync(token);
    }

    private static async Task InsertUserAsync(SqliteConnection connection, SqliteTransaction transaction, AppUser user, CancellationToken token)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "INSERT INTO Users VALUES ($id,$name,$normalized,$display,$password,$role,$enabled,$mustChange,$totp,$recovery,0,NULL,$stamp,$created);";
        command.Parameters.AddWithValue("$id", user.Id.ToString("D")); command.Parameters.AddWithValue("$name", user.UserName);
        command.Parameters.AddWithValue("$normalized", user.NormalizedUserName); command.Parameters.AddWithValue("$display", user.DisplayName);
        command.Parameters.AddWithValue("$password", user.PasswordHash); command.Parameters.AddWithValue("$role", (int)user.Role);
        command.Parameters.AddWithValue("$enabled", user.Enabled); command.Parameters.AddWithValue("$mustChange", user.MustChangePassword);
        command.Parameters.AddWithValue("$totp", user.ProtectedTotpSecret); command.Parameters.AddWithValue("$recovery", user.RecoveryCodeHashesJson);
        command.Parameters.AddWithValue("$stamp", user.SecurityStamp); command.Parameters.AddWithValue("$created", user.CreatedAtUtc.ToUniversalTime().ToString("O"));
        await command.ExecuteNonQueryAsync(token);
    }

    private static AppUser ReadUser(SqliteDataReader reader) => new()
    {
        Id = Guid.Parse(reader.GetString(0)), UserName = reader.GetString(1), NormalizedUserName = reader.GetString(2), DisplayName = reader.GetString(3),
        PasswordHash = reader.GetString(4), Role = (ForensicRole)reader.GetInt32(5), Enabled = reader.GetBoolean(6), MustChangePassword = reader.GetBoolean(7),
        ProtectedTotpSecret = reader.GetString(8), RecoveryCodeHashesJson = reader.GetString(9), FailedAccessCount = reader.GetInt32(10),
        LockoutEndUtc = reader.IsDBNull(11) ? null : DateTimeOffset.Parse(reader.GetString(11), CultureInfo.InvariantCulture), SecurityStamp = reader.GetString(12),
        CreatedAtUtc = DateTimeOffset.Parse(reader.GetString(13), CultureInfo.InvariantCulture)
    };

    private static string Normalize(string value) => value.Trim().ToUpperInvariant();
    private static AuthenticationResult Failure() => new(false, "Credenciales o código MFA no válidos.", null, false, false);
    private static bool PasswordIsStrong(string password, out string error)
    {
        if (password.Length < 14 || !password.Any(char.IsUpper) || !password.Any(char.IsLower) || !password.Any(char.IsDigit) || !password.Any(ch => !char.IsLetterOrDigit(ch)))
        { error = "La contraseña requiere al menos 14 caracteres, mayúscula, minúscula, número y símbolo."; return false; }
        error = string.Empty; return true;
    }
    private static IReadOnlyList<string> GenerateRecoveryCodes() => Enumerable.Range(0, 10).Select(_ => Convert.ToHexString(RandomNumberGenerator.GetBytes(8))).ToArray();
    private static string HashRecoveryCode(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value.Trim().ToUpperInvariant())));

    public static bool VerifyTotp(string secret, string code, DateTimeOffset now)
    {
        if (code.Length != 6 || !code.All(char.IsDigit)) return false;
        var key = Base32Decode(secret);
        var counter = now.ToUnixTimeSeconds() / 30;
        Span<byte> bytes = stackalloc byte[8];
        for (var drift = -1; drift <= 1; drift++)
        {
            System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(bytes, counter + drift);
            var hash = HMACSHA1.HashData(key, bytes);
            var offset = hash[^1] & 0x0f;
            var binary = ((hash[offset] & 0x7f) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3];
            if ((binary % 1_000_000).ToString("D6", CultureInfo.InvariantCulture) == code) return true;
        }
        return false;
    }

    public static string GenerateTotpCode(string secret, DateTimeOffset now)
    {
        var key = Base32Decode(secret);
        Span<byte> bytes = stackalloc byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(bytes, now.ToUnixTimeSeconds() / 30);
        var hash = HMACSHA1.HashData(key, bytes);
        var offset = hash[^1] & 0x0f;
        var binary = ((hash[offset] & 0x7f) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3];
        return (binary % 1_000_000).ToString("D6", CultureInfo.InvariantCulture);
    }

    private static string Base32Encode(byte[] bytes)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var output = new StringBuilder(); var buffer = 0; var bits = 0;
        foreach (var value in bytes) { buffer = (buffer << 8) | value; bits += 8; while (bits >= 5) { output.Append(alphabet[(buffer >> (bits - 5)) & 31]); bits -= 5; } }
        if (bits > 0) output.Append(alphabet[(buffer << (5 - bits)) & 31]);
        return output.ToString();
    }
    private static byte[] Base32Decode(string value)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var output = new List<byte>(); var buffer = 0; var bits = 0;
        foreach (var character in value.TrimEnd('=').ToUpperInvariant()) { var index = alphabet.IndexOf(character); if (index < 0) throw new FormatException("Invalid Base32."); buffer = (buffer << 5) | index; bits += 5; if (bits >= 8) { output.Add((byte)(buffer >> (bits - 8))); bits -= 8; } }
        return output.ToArray();
    }
    private sealed record ChallengePayload(string Secret, DateTimeOffset ExpiresAtUtc);
}

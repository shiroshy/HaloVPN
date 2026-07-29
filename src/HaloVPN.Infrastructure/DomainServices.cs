using System.Data;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using HaloVPN.Contracts;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace HaloVPN.Infrastructure;

public sealed class DomainRuleException(string code, string message) : InvalidOperationException(message)
{
    public string Code { get; } = code;
}

public interface ITokenIssuer
{
    AuthTokensResponse Issue(UserEntity user, Guid? deviceId, Guid? familyId = null);
    byte[] HashRefreshToken(string rawToken);
}

public sealed class TokenIssuer : ITokenIssuer
{
    private readonly HaloVpnDbContext _dbContext;
    private readonly TokenOptions _options;
    private readonly TimeProvider _timeProvider;
    private readonly SigningCredentials _signingCredentials;

    public TokenIssuer(HaloVpnDbContext dbContext, IOptions<TokenOptions> options, TimeProvider timeProvider)
    {
        _dbContext = dbContext;
        _options = options.Value;
        _timeProvider = timeProvider;
        if (_options.AccessLifetime < TimeSpan.FromMinutes(5) || _options.AccessLifetime > TimeSpan.FromMinutes(30) ||
            _options.RefreshLifetime < TimeSpan.FromHours(1) || _options.RefreshLifetime > TimeSpan.FromDays(90))
        {
            throw new InvalidOperationException("Token lifetimes are outside the Private MVP bounds.");
        }

        byte[] signingKey;
        try
        {
            signingKey = Convert.FromBase64String(_options.SigningKeyBase64);
        }
        catch (FormatException exception)
        {
            throw new InvalidOperationException("Token signing key is not valid Base64.", exception);
        }

        if (signingKey.Length < 32)
        {
            CryptographicOperations.ZeroMemory(signingKey);
            throw new InvalidOperationException("Token signing key must contain at least 32 random bytes.");
        }

        _signingCredentials = new SigningCredentials(new SymmetricSecurityKey(signingKey), SecurityAlgorithms.HmacSha256);
    }

    public AuthTokensResponse Issue(UserEntity user, Guid? deviceId, Guid? familyId = null)
    {
        var now = _timeProvider.GetUtcNow();
        var accessExpires = now.Add(_options.AccessLifetime);
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = _options.Issuer,
            Audience = _options.Audience,
            IssuedAt = now.UtcDateTime,
            Expires = accessExpires.UtcDateTime,
            SigningCredentials = _signingCredentials,
            Claims = new Dictionary<string, object>
            {
                [JwtRegisteredClaimNames.Sub] = user.Id.ToString("D"),
                [JwtRegisteredClaimNames.UniqueName] = user.Username,
                [JwtRegisteredClaimNames.Jti] = Guid.NewGuid().ToString("D"),
            },
        };
        if (deviceId.HasValue)
        {
            descriptor.Claims["device_id"] = deviceId.Value.ToString("D");
        }

        var accessToken = new JsonWebTokenHandler().CreateToken(descriptor);
        var refreshBytes = RandomNumberGenerator.GetBytes(32);
        try
        {
            var rawRefresh = Base64UrlEncoder.Encode(refreshBytes);
            var refreshExpires = now.Add(_options.RefreshLifetime);
            _dbContext.RefreshTokens.Add(new RefreshTokenEntity
            {
                Id = Guid.NewGuid(),
                FamilyId = familyId ?? Guid.NewGuid(),
                UserId = user.Id,
                User = user,
                DeviceId = deviceId,
                TokenHash = SHA256.HashData(refreshBytes),
                CreatedAt = now,
                ExpiresAt = refreshExpires,
            });
            return new AuthTokensResponse(accessToken, accessExpires, rawRefresh, refreshExpires);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(refreshBytes);
        }
    }

    public byte[] HashRefreshToken(string rawToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rawToken);
        byte[] bytes;
        try
        {
            bytes = Base64UrlEncoder.DecodeBytes(rawToken);
        }
        catch (FormatException exception)
        {
            throw new DomainRuleException("invalid_refresh_token", exception.Message);
        }

        try
        {
            if (bytes.Length != 32)
            {
                throw new DomainRuleException("invalid_refresh_token", "Refresh token has an invalid length.");
            }

            return SHA256.HashData(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }
}

public sealed class AuthService
{
    private readonly HaloVpnDbContext _dbContext;
    private readonly IPasswordHasher _passwordHasher;
    private readonly ITokenIssuer _tokenIssuer;
    private readonly TimeProvider _timeProvider;
    private readonly string _dummyPasswordHash;

    public AuthService(HaloVpnDbContext dbContext, IPasswordHasher passwordHasher, ITokenIssuer tokenIssuer, TimeProvider timeProvider)
    {
        _dbContext = dbContext;
        _passwordHasher = passwordHasher;
        _tokenIssuer = tokenIssuer;
        _timeProvider = timeProvider;
        _dummyPasswordHash = passwordHasher.Hash("Dummy-Password-Only-For-Timing-2026!");
    }

    public async Task<AuthTokensResponse> LoginAsync(string username, string password, CancellationToken cancellationToken)
    {
        string normalized;
        try
        {
            normalized = UsernameNormalizer.Normalize(username);
        }
        catch (ArgumentException)
        {
            _ = _passwordHasher.Verify(password, _dummyPasswordHash);
            throw new DomainRuleException("invalid_credentials", "Invalid username or password.");
        }

        var user = await _dbContext.Users.SingleOrDefaultAsync(value => value.NormalizedUsername == normalized, cancellationToken).ConfigureAwait(false);
        var passwordValid = _passwordHasher.Verify(password, user?.PasswordHash ?? _dummyPasswordHash);
        if (user is null || !passwordValid || user.Status != UserStatus.Active)
        {
            _dbContext.AuditEvents.Add(new AuditEventEntity
            {
                UserId = user?.Id,
                EventType = "login_failure",
                CreatedAt = _timeProvider.GetUtcNow(),
                SafeDetail = user?.Status == UserStatus.Disabled ? "disabled" : "invalid_credentials",
            });
            await _dbContext.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            throw new DomainRuleException("invalid_credentials", "Invalid username or password.");
        }

        var now = _timeProvider.GetUtcNow();
        user.LastLoginAt = now;
        user.UpdatedAt = now;
        _dbContext.AuditEvents.Add(new AuditEventEntity { UserId = user.Id, EventType = "login_success", CreatedAt = now });
        var tokens = _tokenIssuer.Issue(user, null);
        await _dbContext.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return tokens;
    }

    public async Task<AuthTokensResponse> RefreshAsync(string rawToken, CancellationToken cancellationToken)
    {
        var tokenHash = _tokenIssuer.HashRefreshToken(rawToken);
        try
        {
            Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction? transaction = null;
            if (_dbContext.Database.IsRelational())
            {
                transaction = await _dbContext.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken).ConfigureAwait(false);
            }

            await using (transaction)
            {
                var tokenQuery = _dbContext.Database.IsRelational()
                    ? _dbContext.RefreshTokens.FromSqlInterpolated($"SELECT * FROM refresh_tokens WHERE token_hash = {tokenHash} FOR UPDATE")
                    : _dbContext.RefreshTokens;
                var token = await tokenQuery
                .Include(value => value.User)
                .SingleOrDefaultAsync(value => value.TokenHash == tokenHash, cancellationToken)
                .ConfigureAwait(false);
                if (token is null)
                {
                    throw new DomainRuleException("invalid_refresh_token", "Refresh token is invalid.");
                }

                var now = _timeProvider.GetUtcNow();
                if (token.RevokedAt.HasValue)
                {
                    await RevokeFamilyAsync(token.FamilyId, now, cancellationToken).ConfigureAwait(false);
                    _dbContext.AuditEvents.Add(new AuditEventEntity { UserId = token.UserId, DeviceId = token.DeviceId, EventType = "token_reuse_detected", CreatedAt = now });
                    await _dbContext.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
                    await CommitAsync(transaction, cancellationToken).ConfigureAwait(false);
                    throw new DomainRuleException("refresh_token_reused", "Refresh token reuse was detected.");
                }

                if (token.ExpiresAt <= now || token.User.Status != UserStatus.Active)
                {
                    token.RevokedAt = now;
                    await _dbContext.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
                    await CommitAsync(transaction, cancellationToken).ConfigureAwait(false);
                    throw new DomainRuleException("invalid_refresh_token", "Refresh token is expired or disabled.");
                }

                if (token.DeviceId.HasValue)
                {
                    var activeDevice = await _dbContext.Devices.AnyAsync(
                        value => value.Id == token.DeviceId && value.Status == DeviceStatus.Active,
                        cancellationToken).ConfigureAwait(false);
                    if (!activeDevice)
                    {
                        token.RevokedAt = now;
                        await _dbContext.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
                        await CommitAsync(transaction, cancellationToken).ConfigureAwait(false);
                        throw new DomainRuleException("device_revoked", "The device is revoked.");
                    }
                }

                token.RevokedAt = now;
                var replacement = _tokenIssuer.Issue(token.User, token.DeviceId, token.FamilyId);
                var replacementEntity = _dbContext.RefreshTokens.Local.Last();
                token.ReplacedByTokenId = replacementEntity.Id;
                await _dbContext.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
                await CommitAsync(transaction, cancellationToken).ConfigureAwait(false);
                return replacement;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(tokenHash);
        }
    }

    private static Task CommitAsync(
        Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction? transaction,
        CancellationToken cancellationToken) => transaction is null
        ? Task.CompletedTask
        : transaction.CommitAsync(cancellationToken);

    public async Task LogoutAsync(string rawToken, CancellationToken cancellationToken)
    {
        var tokenHash = _tokenIssuer.HashRefreshToken(rawToken);
        try
        {
            var token = await _dbContext.RefreshTokens.SingleOrDefaultAsync(value => value.TokenHash == tokenHash, cancellationToken).ConfigureAwait(false);
            if (token is not null && !token.RevokedAt.HasValue)
            {
                token.RevokedAt = _timeProvider.GetUtcNow();
                _dbContext.AuditEvents.Add(new AuditEventEntity { UserId = token.UserId, DeviceId = token.DeviceId, EventType = "token_revoked", CreatedAt = token.RevokedAt.Value });
                await _dbContext.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(tokenHash);
        }
    }

    public async Task RevokeAllAsync(Guid userId, CancellationToken cancellationToken)
    {
        var now = _timeProvider.GetUtcNow();
        var tokens = await _dbContext.RefreshTokens
            .Where(value => value.UserId == userId && value.RevokedAt == null)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        foreach (var token in tokens)
        {
            token.RevokedAt = now;
        }
        _dbContext.AuditEvents.Add(new AuditEventEntity { UserId = userId, EventType = "token_revoke_all", CreatedAt = now });
        await _dbContext.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task RevokeFamilyAsync(Guid familyId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        if (_dbContext.Database.IsRelational())
        {
            await _dbContext.RefreshTokens
                .Where(value => value.FamilyId == familyId && value.RevokedAt == null)
                .ExecuteUpdateAsync(setters => setters.SetProperty(value => value.RevokedAt, now), cancellationToken)
                .ConfigureAwait(false);
            return;
        }

        var tokens = await _dbContext.RefreshTokens
            .Where(value => value.FamilyId == familyId && value.RevokedAt == null)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        foreach (var token in tokens)
        {
            token.RevokedAt = now;
        }
    }
}

public sealed class LeaseAllocationLock
{
    internal SemaphoreSlim Semaphore { get; } = new(1, 1);
}

public sealed class DeviceService(
    HaloVpnDbContext dbContext,
    ITokenIssuer tokenIssuer,
    IOptions<VpnNodeSeedOptions> nodeOptions,
    LeaseAllocationLock allocationLock,
    TimeProvider timeProvider)
{
    private readonly VpnNodeSeedOptions _nodeOptions = nodeOptions.Value;

    public async Task<DeviceRegistrationResponse> RegisterAsync(
        Guid userId,
        string name,
        byte[] noisePublicKey,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Trim().Length > 80 || noisePublicKey.Length != 32)
        {
            throw new DomainRuleException("invalid_device", "Device name or public key is invalid.");
        }

        await allocationLock.Semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            IDbContextTransaction? transaction = null;
            if (dbContext.Database.IsRelational())
            {
                transaction = await dbContext.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
            }

            await using (transaction)
            {
                var user = await dbContext.Users.Include(value => value.Devices).SingleOrDefaultAsync(value => value.Id == userId, cancellationToken).ConfigureAwait(false)
                    ?? throw new DomainRuleException("user_not_found", "User does not exist.");
                if (user.Status != UserStatus.Active)
                {
                    throw new DomainRuleException("user_disabled", "User is disabled.");
                }

                var existingDevice = await dbContext.Devices.SingleOrDefaultAsync(value => value.NoisePublicKey == noisePublicKey, cancellationToken).ConfigureAwait(false);
                if (existingDevice is not null)
                {
                    if (existingDevice.UserId != user.Id || existingDevice.Status != DeviceStatus.Active)
                    {
                        throw new DomainRuleException("duplicate_public_key", "The device public key is already registered or revoked.");
                    }

                    var existingNode = await dbContext.VpnNodes.SingleOrDefaultAsync(value => value.Enabled, cancellationToken).ConfigureAwait(false)
                        ?? throw new DomainRuleException("node_unavailable", "No enabled VPN node is configured.");
                    var existingTokens = tokenIssuer.Issue(user, existingDevice.Id);
                    await dbContext.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
                    if (transaction is not null)
                    {
                        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
                    }

                    return new DeviceRegistrationResponse(existingDevice.Id, existingTokens, CreateProfile(existingDevice, existingNode));
                }

                if (user.Devices.Count(value => value.Status == DeviceStatus.Active) >= user.MaxDevices)
                {
                    throw new DomainRuleException("device_limit", "The user device limit has been reached.");
                }

                var node = await dbContext.VpnNodes.SingleOrDefaultAsync(value => value.Enabled, cancellationToken).ConfigureAwait(false)
                    ?? throw new DomainRuleException("node_unavailable", "No enabled VPN node is configured.");
                var subnet = Ipv4Subnet.Parse(node.TunnelSubnet);
                var gateway = IPAddress.Parse(_nodeOptions.TunnelGateway);
                var used = await dbContext.Devices.Select(value => value.AssignedTunnelIp).ToListAsync(cancellationToken).ConfigureAwait(false);
                var usedValues = used.Select(Ipv4Subnet.ToUInt32).ToHashSet();
                var address = subnet.UsableAddresses(gateway).FirstOrDefault(value => !usedValues.Contains(Ipv4Subnet.ToUInt32(value)))
                    ?? throw new DomainRuleException("address_pool_exhausted", "The tunnel address pool is exhausted.");
                var now = timeProvider.GetUtcNow();
                var device = new DeviceEntity
                {
                    Id = Guid.NewGuid(),
                    UserId = user.Id,
                    User = user,
                    Name = name.Trim(),
                    NoisePublicKey = noisePublicKey.ToArray(),
                    AssignedTunnelIp = address,
                    Status = DeviceStatus.Active,
                    CreatedAt = now,
                };
                dbContext.Devices.Add(device);
                dbContext.AuditEvents.Add(new AuditEventEntity { UserId = user.Id, DeviceId = device.Id, EventType = "device_registered", CreatedAt = now });
                var tokens = tokenIssuer.Issue(user, device.Id);
                await dbContext.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
                if (transaction is not null)
                {
                    await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
                }

                return new DeviceRegistrationResponse(device.Id, tokens, CreateProfile(device, node));
            }
        }
        catch (DbUpdateException exception)
        {
            throw new DomainRuleException("registration_conflict", $"Device registration conflicted with another transaction: {exception.GetType().Name}.");
        }
        finally
        {
            allocationLock.Semaphore.Release();
        }
    }

    public async Task<IReadOnlyList<DeviceResponse>> ListAsync(Guid userId, CancellationToken cancellationToken) =>
        await dbContext.Devices.Where(value => value.UserId == userId)
            .OrderBy(value => value.CreatedAt)
            .Select(value => new DeviceResponse(value.Id, value.Name, value.AssignedTunnelIp.ToString(), value.Status, value.CreatedAt, value.LastSeenAt))
            .ToListAsync(cancellationToken).ConfigureAwait(false);

    public async Task<VpnProfileResponse> GetProfileAsync(Guid userId, Guid deviceId, CancellationToken cancellationToken)
    {
        var device = await dbContext.Devices.Include(value => value.User)
            .SingleOrDefaultAsync(value => value.Id == deviceId && value.UserId == userId, cancellationToken).ConfigureAwait(false)
            ?? throw new DomainRuleException("device_not_found", "Device does not exist.");
        if (device.Status != DeviceStatus.Active || device.User.Status != UserStatus.Active)
        {
            throw new DomainRuleException("device_revoked", "Device or user is disabled.");
        }

        var node = await dbContext.VpnNodes.SingleOrDefaultAsync(value => value.Enabled, cancellationToken).ConfigureAwait(false)
            ?? throw new DomainRuleException("node_unavailable", "No enabled VPN node is configured.");
        return CreateProfile(device, node);
    }

    public async Task RevokeAsync(Guid userId, Guid deviceId, CancellationToken cancellationToken)
    {
        var device = await dbContext.Devices.SingleOrDefaultAsync(value => value.Id == deviceId && value.UserId == userId, cancellationToken).ConfigureAwait(false)
            ?? throw new DomainRuleException("device_not_found", "Device does not exist.");
        if (device.Status == DeviceStatus.Revoked)
        {
            return;
        }

        var now = timeProvider.GetUtcNow();
        device.Status = DeviceStatus.Revoked;
        device.RevokedAt = now;
        var tokens = await dbContext.RefreshTokens.Where(value => value.DeviceId == deviceId && value.RevokedAt == null)
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        foreach (var token in tokens)
        {
            token.RevokedAt = now;
        }
        dbContext.AuditEvents.Add(new AuditEventEntity { UserId = userId, DeviceId = deviceId, EventType = "device_revoked", CreatedAt = now });
        await dbContext.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    private VpnProfileResponse CreateProfile(DeviceEntity device, VpnNodeEntity node) => new(
        device.Id,
        node.Name,
        node.PublicHost,
        node.UdpPort,
        Convert.ToBase64String(node.PublicKey),
        device.AssignedTunnelIp.ToString(),
        _nodeOptions.TunnelGateway,
        Ipv4Subnet.Parse(_nodeOptions.TunnelSubnet).PrefixLength,
        node.Mtu,
        node.DnsServers
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.Ordinal)
            .ToArray(),
        0);
}

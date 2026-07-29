using HaloVPN.Contracts;
using Microsoft.EntityFrameworkCore;

namespace HaloVPN.Infrastructure;

public sealed class AdminService(
    HaloVpnDbContext dbContext,
    IPasswordHasher passwordHasher,
    TimeProvider timeProvider)
{
    public async Task<UserEntity> CreateUserAsync(string username, string password, int maxDevices, CancellationToken cancellationToken)
    {
        var normalized = UsernameNormalizer.Normalize(username);
        if (maxDevices is < 1 or > 16)
        {
            throw new DomainRuleException("invalid_device_limit", "MaxDevices must be between 1 and 16.");
        }

        if (await dbContext.Users.AnyAsync(value => value.NormalizedUsername == normalized, cancellationToken).ConfigureAwait(false))
        {
            throw new DomainRuleException("duplicate_username", "Username already exists.");
        }

        var now = timeProvider.GetUtcNow();
        var user = new UserEntity
        {
            Id = Guid.NewGuid(),
            Username = username.Trim(),
            NormalizedUsername = normalized,
            PasswordHash = passwordHasher.Hash(password),
            Status = UserStatus.Active,
            MaxDevices = maxDevices,
            CreatedAt = now,
            UpdatedAt = now,
        };
        dbContext.Users.Add(user);
        dbContext.AuditEvents.Add(new AuditEventEntity { UserId = user.Id, EventType = "user_created", CreatedAt = now });
        await dbContext.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return user;
    }

    public Task<List<UserEntity>> ListUsersAsync(CancellationToken cancellationToken) =>
        dbContext.Users.AsNoTracking().OrderBy(value => value.Username).ToListAsync(cancellationToken);

    public async Task SetEnabledAsync(string username, bool enabled, CancellationToken cancellationToken)
    {
        var normalized = UsernameNormalizer.Normalize(username);
        var user = await dbContext.Users.SingleOrDefaultAsync(value => value.NormalizedUsername == normalized, cancellationToken).ConfigureAwait(false)
            ?? throw new DomainRuleException("user_not_found", "User does not exist.");
        var now = timeProvider.GetUtcNow();
        user.Status = enabled ? UserStatus.Active : UserStatus.Disabled;
        user.UpdatedAt = now;
        if (!enabled)
        {
            var tokens = await dbContext.RefreshTokens.Where(value => value.UserId == user.Id && value.RevokedAt == null).ToListAsync(cancellationToken).ConfigureAwait(false);
            foreach (var token in tokens)
            {
                token.RevokedAt = now;
            }
        }

        dbContext.AuditEvents.Add(new AuditEventEntity { UserId = user.Id, EventType = enabled ? "user_enabled" : "user_disabled", CreatedAt = now });
        await dbContext.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task ResetPasswordAsync(string username, string password, CancellationToken cancellationToken)
    {
        var normalized = UsernameNormalizer.Normalize(username);
        var user = await dbContext.Users.SingleOrDefaultAsync(value => value.NormalizedUsername == normalized, cancellationToken).ConfigureAwait(false)
            ?? throw new DomainRuleException("user_not_found", "User does not exist.");
        var now = timeProvider.GetUtcNow();
        user.PasswordHash = passwordHasher.Hash(password);
        user.UpdatedAt = now;
        var tokens = await dbContext.RefreshTokens.Where(value => value.UserId == user.Id && value.RevokedAt == null).ToListAsync(cancellationToken).ConfigureAwait(false);
        foreach (var token in tokens)
        {
            token.RevokedAt = now;
        }
        dbContext.AuditEvents.Add(new AuditEventEntity { UserId = user.Id, EventType = "password_reset", CreatedAt = now });
        await dbContext.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<DeviceEntity>> ListDevicesAsync(string username, CancellationToken cancellationToken)
    {
        var normalized = UsernameNormalizer.Normalize(username);
        return await dbContext.Devices.AsNoTracking().Where(value => value.User.NormalizedUsername == normalized)
            .OrderBy(value => value.CreatedAt).ToListAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task RevokeDeviceAsync(Guid deviceId, CancellationToken cancellationToken)
    {
        var device = await dbContext.Devices.SingleOrDefaultAsync(value => value.Id == deviceId, cancellationToken).ConfigureAwait(false)
            ?? throw new DomainRuleException("device_not_found", "Device does not exist.");
        var now = timeProvider.GetUtcNow();
        device.Status = DeviceStatus.Revoked;
        device.RevokedAt = now;
        var tokens = await dbContext.RefreshTokens.Where(value => value.DeviceId == deviceId && value.RevokedAt == null).ToListAsync(cancellationToken).ConfigureAwait(false);
        foreach (var token in tokens)
        {
            token.RevokedAt = now;
        }
        dbContext.AuditEvents.Add(new AuditEventEntity { UserId = device.UserId, DeviceId = device.Id, EventType = "device_revoked", CreatedAt = now });
        await dbContext.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }
}

using System.Net;
using HaloVPN.Contracts;

namespace HaloVPN.Infrastructure;

public sealed class UserEntity
{
    public Guid Id { get; set; }
    public required string Username { get; set; }
    public required string NormalizedUsername { get; set; }
    public required string PasswordHash { get; set; }
    public UserStatus Status { get; set; }
    public int MaxDevices { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
    public DateTimeOffset? LastLoginAt { get; set; }
    public List<DeviceEntity> Devices { get; } = [];
    public List<RefreshTokenEntity> RefreshTokens { get; } = [];
}

public sealed class DeviceEntity
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public required UserEntity User { get; set; }
    public required string Name { get; set; }
    public required byte[] NoisePublicKey { get; set; }
    public required IPAddress AssignedTunnelIp { get; set; }
    public DeviceStatus Status { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? LastSeenAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
    public List<RefreshTokenEntity> RefreshTokens { get; } = [];
}

public sealed class RefreshTokenEntity
{
    public Guid Id { get; set; }
    public Guid FamilyId { get; set; }
    public Guid UserId { get; set; }
    public required UserEntity User { get; set; }
    public Guid? DeviceId { get; set; }
    public DeviceEntity? Device { get; set; }
    public required byte[] TokenHash { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
    public Guid? ReplacedByTokenId { get; set; }
}

public sealed class VpnNodeEntity
{
    public Guid Id { get; set; }
    public required string Name { get; set; }
    public required byte[] PublicKey { get; set; }
    public required string PublicHost { get; set; }
    public ushort UdpPort { get; set; }
    public required string TunnelSubnet { get; set; }
    public required string DnsServers { get; set; }
    public int Mtu { get; set; }
    public bool Enabled { get; set; }
}

public sealed class AuditEventEntity
{
    public long Id { get; set; }
    public Guid? UserId { get; set; }
    public Guid? DeviceId { get; set; }
    public required string EventType { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public string? SafeDetail { get; set; }
}

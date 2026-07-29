namespace HaloVPN.Contracts;

public enum UserStatus
{
    Active = 0,
    Disabled = 1,
}

public enum DeviceStatus
{
    Active = 0,
    Revoked = 1,
}

public sealed record LoginRequest(string Username, string Password);

public sealed record RefreshRequest(string RefreshToken);

public sealed record LogoutRequest(string RefreshToken);

public sealed record RegisterDeviceRequest(string Name, string NoisePublicKey);

public sealed record AuthTokensResponse(
    string AccessToken,
    DateTimeOffset AccessTokenExpiresAt,
    string RefreshToken,
    DateTimeOffset RefreshTokenExpiresAt);

public sealed record DeviceRegistrationResponse(
    Guid DeviceId,
    AuthTokensResponse Tokens,
    VpnProfileResponse Profile);

public sealed record DeviceResponse(
    Guid Id,
    string Name,
    string AssignedTunnelIp,
    DeviceStatus Status,
    DateTimeOffset CreatedAt,
    DateTimeOffset? LastSeenAt);

public sealed record VpnProfileResponse(
    Guid DeviceId,
    string NodeName,
    string PublicHost,
    ushort UdpPort,
    string NodeNoisePublicKey,
    string AssignedClientIpv4,
    string TunnelGateway,
    int TunnelPrefixLength,
    int Mtu,
    IReadOnlyList<string> DnsServers,
    byte ProtocolVersion);

public sealed record ApiErrorResponse(string Code, string Message);

public sealed record ServiceStatusResponse(string State, string? AssignedTunnelIp, string? DiagnosticCode);

public static class UsernameNormalizer
{
    public static string Normalize(string username)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(username);
        var trimmed = username.Trim();
        if (trimmed.Length is < 3 or > 64)
        {
            throw new ArgumentException("Username length must be between 3 and 64 characters.", nameof(username));
        }

        foreach (var character in trimmed)
        {
            if (!(char.IsAsciiLetterOrDigit(character) || character is '.' or '_' or '-'))
            {
                throw new ArgumentException("Username contains an unsupported character.", nameof(username));
            }
        }

        return trimmed.ToUpperInvariant();
    }
}

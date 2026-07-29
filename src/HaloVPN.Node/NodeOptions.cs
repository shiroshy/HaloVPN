using HaloVPN.Node.Core;

namespace HaloVPN.Node;

public sealed record NodeOptions
{
    public const string SectionName = "Node";
    public string ListenAddress { get; init; } = "0.0.0.0";
    public int UdpPort { get; init; } = 45000;
    public string PrivateKeyPath { get; init; } = "/etc/halovpn/node.key";
    public string TunName { get; init; } = "halo0";
    public string TunnelGatewayCidr { get; init; } = "10.77.0.1/24";
    public int Mtu { get; init; } = 1200;
    public int MaximumActiveSessions { get; init; } = 16;
    public int MaximumPendingHandshakes { get; init; } = 32;
    public int MaximumPendingPerSource { get; init; } = 4;
    public int MaximumAttemptsPerSourceWindow { get; init; } = 12;
    public TimeSpan HandshakeAttemptWindow { get; init; } = TimeSpan.FromSeconds(10);
    public TimeSpan IdleTimeout { get; init; } = TimeSpan.FromMinutes(3);
    public int MaximumCachedDevices { get; init; } = 64;
    public TimeSpan AuthorizationRefreshInterval { get; init; } = TimeSpan.FromSeconds(15);
    public TimeSpan MaximumAuthorizationStaleAge { get; init; } = TimeSpan.FromMinutes(2);
    public string[] DeniedDestinationCidrs { get; init; } = DestinationPolicyOptions.DefaultDeniedCidrs;
    public string[] AllowedDestinationCidrs { get; init; } = [];
    public int MaximumHandshakeResponseCacheEntries { get; init; } = 128;
    public int MaximumHandshakeResponseCacheEntriesPerSource { get; init; } = 8;
    public TimeSpan HandshakeResponseCacheTtl { get; init; } = TimeSpan.FromSeconds(15);
}

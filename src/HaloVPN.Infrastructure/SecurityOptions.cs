namespace HaloVPN.Infrastructure;

public sealed record TokenOptions
{
    public const string SectionName = "Tokens";
    public required string Issuer { get; init; }
    public required string Audience { get; init; }
    public required string SigningKeyBase64 { get; init; }
    public TimeSpan AccessLifetime { get; init; } = TimeSpan.FromMinutes(15);
    public TimeSpan RefreshLifetime { get; init; } = TimeSpan.FromDays(30);
}

public sealed record Argon2Options
{
    public int MemorySizeKiB { get; init; } = 65_536;
    public int Iterations { get; init; } = 3;
    public int DegreeOfParallelism { get; init; } = 2;
    public int SaltSize { get; init; } = 16;
    public int HashSize { get; init; } = 32;
}

public sealed record VpnNodeSeedOptions
{
    public const string SectionName = "VpnNode";
    public string Name { get; init; } = "Astana-1";
    public string PublicHost { get; init; } = string.Empty;
    public ushort UdpPort { get; init; } = 45000;
    public string PublicKeyBase64 { get; init; } = string.Empty;
    public string TunnelSubnet { get; init; } = "10.77.0.0/24";
    public string TunnelGateway { get; init; } = "10.77.0.1";
    public string[] DnsServers { get; init; } = ["1.1.1.1"];
    public int Mtu { get; init; } = 1200;
}

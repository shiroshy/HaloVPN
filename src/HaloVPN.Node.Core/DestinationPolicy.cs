using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace HaloVPN.Node.Core;

public enum DestinationPolicyResult
{
    Allowed = 0,
    DeniedAbsolute,
    DeniedTunnel,
    DeniedLocal,
    DeniedConfigured,
}

public readonly record struct Ipv4Cidr(uint Network, uint Mask, int PrefixLength)
{
    public static Ipv4Cidr Parse(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        var separator = value.LastIndexOf('/');
        if (separator <= 0 || !IPAddress.TryParse(value[..separator], out var address) ||
            address.AddressFamily != AddressFamily.InterNetwork ||
            !int.TryParse(value[(separator + 1)..], out var prefix) || prefix is < 0 or > 32)
        {
            throw new FormatException("Destination CIDR must be an IPv4 prefix between /0 and /32.");
        }

        var raw = BinaryPrimitives.ReadUInt32BigEndian(address.GetAddressBytes());
        var mask = prefix == 0 ? 0 : uint.MaxValue << (32 - prefix);
        if ((raw & mask) != raw)
        {
            throw new FormatException("Destination CIDR must use its network address.");
        }

        return new Ipv4Cidr(raw, mask, prefix);
    }

    public bool Contains(uint address) => (address & Mask) == Network;
}

public sealed record DestinationPolicyOptions
{
    public static readonly string[] DefaultDeniedCidrs =
    [
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
        "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
        "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
    ];

    public IReadOnlyList<string> DeniedDestinationCidrs { get; init; } = DefaultDeniedCidrs;
    public IReadOnlyList<string> AllowedDestinationCidrs { get; init; } = [];
    public required string TunnelSubnet { get; init; }
    public IReadOnlyList<IPAddress> LocalAddresses { get; init; } = [];
}

public sealed class DestinationPolicy
{
    private static readonly Ipv4Cidr[] AbsoluteDenials =
    [
        Ipv4Cidr.Parse("0.0.0.0/8"),
        Ipv4Cidr.Parse("127.0.0.0/8"),
        Ipv4Cidr.Parse("224.0.0.0/4"),
        Ipv4Cidr.Parse("240.0.0.0/4"),
    ];

    private readonly Ipv4Cidr _tunnelSubnet;
    private readonly Ipv4Cidr[] _denied;
    private readonly Ipv4Cidr[] _allowed;
    private readonly HashSet<uint> _localAddresses;

    public DestinationPolicy(DestinationPolicyOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.DeniedDestinationCidrs.Count > 256 || options.AllowedDestinationCidrs.Count > 64 || options.LocalAddresses.Count > 256)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "Destination policy bounds were exceeded.");
        }

        _tunnelSubnet = Ipv4Cidr.Parse(options.TunnelSubnet);
        _denied = options.DeniedDestinationCidrs.Select(Ipv4Cidr.Parse).ToArray();
        _allowed = options.AllowedDestinationCidrs.Select(Ipv4Cidr.Parse).ToArray();
        _localAddresses = options.LocalAddresses
            .Where(value => value.AddressFamily == AddressFamily.InterNetwork)
            .Select(value => BinaryPrimitives.ReadUInt32BigEndian(value.GetAddressBytes()))
            .ToHashSet();
    }

    public DestinationPolicyResult Evaluate(IPAddress destination)
    {
        ArgumentNullException.ThrowIfNull(destination);
        if (destination.AddressFamily != AddressFamily.InterNetwork)
        {
            return DestinationPolicyResult.DeniedAbsolute;
        }

        var raw = BinaryPrimitives.ReadUInt32BigEndian(destination.GetAddressBytes());
        if (AbsoluteDenials.Any(value => value.Contains(raw)))
        {
            return DestinationPolicyResult.DeniedAbsolute;
        }

        if (_tunnelSubnet.Contains(raw))
        {
            return DestinationPolicyResult.DeniedTunnel;
        }

        if (_localAddresses.Contains(raw))
        {
            return DestinationPolicyResult.DeniedLocal;
        }

        if (_allowed.Any(value => value.Contains(raw)))
        {
            return DestinationPolicyResult.Allowed;
        }

        return _denied.Any(value => value.Contains(raw))
            ? DestinationPolicyResult.DeniedConfigured
            : DestinationPolicyResult.Allowed;
    }
}

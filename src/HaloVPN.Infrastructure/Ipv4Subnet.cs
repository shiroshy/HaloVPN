using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace HaloVPN.Infrastructure;

public readonly record struct Ipv4Subnet(uint Network, int PrefixLength)
{
    public uint Mask => PrefixLength == 0 ? 0 : uint.MaxValue << (32 - PrefixLength);
    public uint Broadcast => Network | ~Mask;

    public static Ipv4Subnet Parse(string cidr)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(cidr);
        var separator = cidr.LastIndexOf('/');
        if (separator <= 0 || !IPAddress.TryParse(cidr[..separator], out var address) ||
            address.AddressFamily != AddressFamily.InterNetwork ||
            !int.TryParse(cidr[(separator + 1)..], out var prefix) || prefix is < 8 or > 30)
        {
            throw new FormatException("Tunnel subnet must be an IPv4 CIDR with prefix /8 through /30.");
        }

        var raw = ToUInt32(address);
        var mask = uint.MaxValue << (32 - prefix);
        if ((raw & mask) != raw)
        {
            throw new FormatException("Tunnel subnet address must be the network address.");
        }

        return new Ipv4Subnet(raw, prefix);
    }

    public bool Contains(IPAddress address) => (ToUInt32(address) & Mask) == Network;

    public IEnumerable<IPAddress> UsableAddresses(IPAddress gateway)
    {
        var gatewayValue = ToUInt32(gateway);
        if (!Contains(gateway) || gatewayValue == Network || gatewayValue == Broadcast)
        {
            throw new ArgumentException("Gateway must be a usable address inside the tunnel subnet.", nameof(gateway));
        }

        for (var value = Network + 1; value < Broadcast; value++)
        {
            if (value != gatewayValue)
            {
                yield return FromUInt32(value);
            }
        }
    }

    public static uint ToUInt32(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        var bytes = address.GetAddressBytes();
        if (bytes.Length != 4)
        {
            throw new ArgumentException("Only IPv4 addresses are supported.", nameof(address));
        }

        return BinaryPrimitives.ReadUInt32BigEndian(bytes);
    }

    public static IPAddress FromUInt32(uint value)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        return new IPAddress(bytes);
    }
}

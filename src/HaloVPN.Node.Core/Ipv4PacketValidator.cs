using System.Buffers.Binary;
using System.Net;
using HaloVPN.Infrastructure;

namespace HaloVPN.Node.Core;

public enum PacketValidationResult
{
    Accepted = 0,
    Malformed,
    SourceSpoofed,
    ClientToClient,
    MulticastOrBroadcast,
    UnknownDestination,
}

public readonly record struct Ipv4PacketInfo(IPAddress Source, IPAddress Destination, int TotalLength);

public static class Ipv4PacketValidator
{
    public static bool TryParse(ReadOnlySpan<byte> packet, int mtu, out Ipv4PacketInfo info)
    {
        info = default;
        if (mtu is < 576 or > 9000 || packet.Length is < 20 || packet.Length > mtu)
        {
            return false;
        }

        var version = packet[0] >> 4;
        var headerLength = (packet[0] & 0x0F) * 4;
        var totalLength = BinaryPrimitives.ReadUInt16BigEndian(packet[2..]);
        if (version != 4 || headerLength < 20 || headerLength > packet.Length || totalLength != packet.Length)
        {
            return false;
        }

        var fragment = BinaryPrimitives.ReadUInt16BigEndian(packet[6..]);
        if ((fragment & 0x3FFF) != 0)
        {
            return false;
        }

        var source = new IPAddress(packet.Slice(12, 4));
        var destination = new IPAddress(packet.Slice(16, 4));
        info = new Ipv4PacketInfo(source, destination, totalLength);
        return true;
    }

    public static PacketValidationResult ValidateFromClient(
        ReadOnlySpan<byte> packet,
        int mtu,
        IPAddress assignedSource,
        IReadOnlySet<uint> activeClientAddresses,
        Ipv4Subnet? tunnelSubnet = null)
    {
        if (!TryParse(packet, mtu, out var info))
        {
            return PacketValidationResult.Malformed;
        }

        var source = Ipv4Subnet.ToUInt32(info.Source);
        var destination = Ipv4Subnet.ToUInt32(info.Destination);
        if (source != Ipv4Subnet.ToUInt32(assignedSource))
        {
            return PacketValidationResult.SourceSpoofed;
        }

        if (IsNonUnicast(destination) ||
            (tunnelSubnet.HasValue && destination is var value && (value == tunnelSubnet.Value.Network || value == tunnelSubnet.Value.Broadcast)))
        {
            return PacketValidationResult.MulticastOrBroadcast;
        }

        return activeClientAddresses.Contains(destination)
            ? PacketValidationResult.ClientToClient
            : PacketValidationResult.Accepted;
    }

    public static PacketValidationResult ValidateFromTun(
        ReadOnlySpan<byte> packet,
        int mtu,
        IReadOnlySet<uint> activeClientAddresses,
        out uint destination)
    {
        destination = 0;
        if (!TryParse(packet, mtu, out var info))
        {
            return PacketValidationResult.Malformed;
        }

        destination = Ipv4Subnet.ToUInt32(info.Destination);
        if (IsNonUnicast(destination))
        {
            return PacketValidationResult.MulticastOrBroadcast;
        }

        return activeClientAddresses.Contains(destination)
            ? PacketValidationResult.Accepted
            : PacketValidationResult.UnknownDestination;
    }

    private static bool IsNonUnicast(uint address) =>
        address == 0 || address == uint.MaxValue || (address & 0xF000_0000) == 0xE000_0000 || (address & 0xFF00_0000) == 0x7F00_0000;
}

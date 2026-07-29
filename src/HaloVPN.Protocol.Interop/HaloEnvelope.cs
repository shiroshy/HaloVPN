using System.Buffers.Binary;
using HaloVPN.Protocol.Abstractions;
using HaloVPN.Shared;

namespace HaloVPN.Protocol.Interop;

public readonly record struct HaloEnvelopeHeader(
    ProtocolMessageType MessageType,
    ushort Flags,
    ulong ConnectionId,
    ulong PacketNumber,
    ushort PayloadLength);

public readonly ref struct ParsedHaloEnvelope
{
    internal ParsedHaloEnvelope(HaloEnvelopeHeader header, ReadOnlySpan<byte> payload)
    {
        Header = header;
        Payload = payload;
    }

    public HaloEnvelopeHeader Header { get; }

    public ReadOnlySpan<byte> Payload { get; }
}

public static class HaloEnvelope
{
    public const int HeaderSize = HaloProtocolConstants.CommonHeaderSize;

    public static bool TryParse(
        ReadOnlySpan<byte> datagram,
        out ParsedHaloEnvelope envelope,
        out ProtocolErrorCode errorCode)
    {
        envelope = default;
        if (datagram.Length < HeaderSize || datagram.Length > HaloProtocolConstants.MaximumAuthenticatedDatagramSize)
        {
            errorCode = ProtocolErrorCode.InvalidPacket;
            return false;
        }

        if (BinaryPrimitives.ReadUInt16BigEndian(datagram) != HaloProtocolConstants.Magic)
        {
            errorCode = ProtocolErrorCode.InvalidPacket;
            return false;
        }

        if (datagram[2] != HaloProtocolConstants.WireVersion)
        {
            errorCode = ProtocolErrorCode.UnsupportedVersion;
            return false;
        }

        var rawType = datagram[3];
        if (!IsKnownMessageType(rawType))
        {
            errorCode = ProtocolErrorCode.InvalidPacket;
            return false;
        }

        var messageType = (ProtocolMessageType)rawType;
        var flags = BinaryPrimitives.ReadUInt16BigEndian(datagram[4..]);
        if (flags != 0)
        {
            errorCode = ProtocolErrorCode.InvalidPacket;
            return false;
        }

        var payloadLength = BinaryPrimitives.ReadUInt16BigEndian(datagram[22..]);
        if (payloadLength > MaximumPayloadFor(messageType) || HeaderSize + payloadLength != datagram.Length)
        {
            errorCode = ProtocolErrorCode.InvalidPacket;
            return false;
        }

        var header = new HaloEnvelopeHeader(
            messageType,
            flags,
            BinaryPrimitives.ReadUInt64BigEndian(datagram[6..]),
            BinaryPrimitives.ReadUInt64BigEndian(datagram[14..]),
            payloadLength);
        envelope = new ParsedHaloEnvelope(header, datagram[HeaderSize..]);
        errorCode = ProtocolErrorCode.None;
        return true;
    }

    public static void WriteHeader(Span<byte> destination, HaloEnvelopeHeader header)
    {
        if (destination.Length < HeaderSize)
        {
            throw new ArgumentException("The destination is smaller than the Halo envelope header.", nameof(destination));
        }

        if (!IsKnownMessageType((byte)header.MessageType) || header.Flags != 0 ||
            header.PayloadLength > MaximumPayloadFor(header.MessageType))
        {
            throw new ArgumentOutOfRangeException(nameof(header));
        }

        BinaryPrimitives.WriteUInt16BigEndian(destination, HaloProtocolConstants.Magic);
        destination[2] = HaloProtocolConstants.WireVersion;
        destination[3] = (byte)header.MessageType;
        BinaryPrimitives.WriteUInt16BigEndian(destination[4..], header.Flags);
        BinaryPrimitives.WriteUInt64BigEndian(destination[6..], header.ConnectionId);
        BinaryPrimitives.WriteUInt64BigEndian(destination[14..], header.PacketNumber);
        BinaryPrimitives.WriteUInt16BigEndian(destination[22..], header.PayloadLength);
    }

    public static int MaximumPayloadFor(ProtocolMessageType messageType) => messageType switch
    {
        ProtocolMessageType.HandshakeInit or ProtocolMessageType.HandshakeResponse => 488,
        ProtocolMessageType.Data => 1244,
        ProtocolMessageType.KeepAlive => 40,
        ProtocolMessageType.Close => 48,
        _ => 0,
    };

    private static bool IsKnownMessageType(byte value) => value is
        (byte)ProtocolMessageType.HandshakeInit or
        (byte)ProtocolMessageType.HandshakeResponse or
        (byte)ProtocolMessageType.Data or
        (byte)ProtocolMessageType.KeepAlive or
        (byte)ProtocolMessageType.Close;
}

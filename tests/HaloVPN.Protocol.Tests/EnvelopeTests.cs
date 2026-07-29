using System.Buffers.Binary;
using HaloVPN.Protocol.Abstractions;
using HaloVPN.Protocol.Interop;
using HaloVPN.Shared;

namespace HaloVPN.Protocol.Tests;

public sealed class EnvelopeTests
{
    public static TheoryData<ProtocolMessageType> MessageTypes => new()
    {
        ProtocolMessageType.HandshakeInit,
        ProtocolMessageType.HandshakeResponse,
        ProtocolMessageType.Data,
        ProtocolMessageType.KeepAlive,
        ProtocolMessageType.Close,
    };

    [Theory]
    [MemberData(nameof(MessageTypes))]
    public void SerializeAndParseEveryMessageType(ProtocolMessageType messageType)
    {
        var payloadLength = Math.Min(16, HaloEnvelope.MaximumPayloadFor(messageType));
        var datagram = new byte[HaloEnvelope.HeaderSize + payloadLength];
        var expected = new HaloEnvelopeHeader(messageType, 0, 0x0102_0304_0506_0708, 42, (ushort)payloadLength);

        HaloEnvelope.WriteHeader(datagram, expected);
        datagram.AsSpan(HaloEnvelope.HeaderSize).Fill(0xA5);

        Assert.True(HaloEnvelope.TryParse(datagram, out var parsed, out var error));
        Assert.Equal(ProtocolErrorCode.None, error);
        Assert.Equal(expected, parsed.Header);
        Assert.True(parsed.Payload.SequenceEqual(datagram.AsSpan(HaloEnvelope.HeaderSize)));
        Assert.Equal(HaloProtocolConstants.Magic, BinaryPrimitives.ReadUInt16BigEndian(datagram));
    }

    [Fact]
    public void RejectsUnknownVersionInvalidMagicAndTruncatedHeader()
    {
        var valid = Create(ProtocolMessageType.Data, 16);
        valid[2] = 1;
        Assert.False(HaloEnvelope.TryParse(valid, out _, out var versionError));
        Assert.Equal(ProtocolErrorCode.UnsupportedVersion, versionError);

        valid = Create(ProtocolMessageType.Data, 16);
        valid[0] ^= 1;
        Assert.False(HaloEnvelope.TryParse(valid, out _, out var magicError));
        Assert.Equal(ProtocolErrorCode.InvalidPacket, magicError);

        Assert.False(HaloEnvelope.TryParse(new byte[HaloEnvelope.HeaderSize - 1], out _, out var shortError));
        Assert.Equal(ProtocolErrorCode.InvalidPacket, shortError);
    }

    [Fact]
    public void RejectsInconsistentOversizedAndTrailingPayloads()
    {
        var shorter = Create(ProtocolMessageType.Data, 16);
        BinaryPrimitives.WriteUInt16BigEndian(shorter.AsSpan(22), 17);
        Assert.False(HaloEnvelope.TryParse(shorter, out _, out _));

        var oversized = new byte[HaloEnvelope.HeaderSize];
        HaloEnvelope.WriteHeader(oversized, new HaloEnvelopeHeader(ProtocolMessageType.KeepAlive, 0, 1, 0, 0));
        BinaryPrimitives.WriteUInt16BigEndian(oversized.AsSpan(22), 65);
        Assert.False(HaloEnvelope.TryParse(oversized, out _, out _));

        var trailing = Create(ProtocolMessageType.Close, 24);
        Array.Resize(ref trailing, trailing.Length + 1);
        Assert.False(HaloEnvelope.TryParse(trailing, out _, out _));
    }

    [Fact]
    public void RandomInputNeverThrows()
    {
        var random = new Random(123_456);
        for (var iteration = 0; iteration < 10_000; iteration++)
        {
            var bytes = new byte[random.Next(0, 1500)];
            random.NextBytes(bytes);
            _ = HaloEnvelope.TryParse(bytes, out _, out _);
        }
    }

    private static byte[] Create(ProtocolMessageType messageType, ushort payloadLength)
    {
        var datagram = new byte[HaloEnvelope.HeaderSize + payloadLength];
        HaloEnvelope.WriteHeader(datagram, new HaloEnvelopeHeader(messageType, 0, 1, 0, payloadLength));
        return datagram;
    }
}

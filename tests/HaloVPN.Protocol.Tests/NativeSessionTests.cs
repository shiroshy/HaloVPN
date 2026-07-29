using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using HaloVPN.Protocol.Abstractions;
using HaloVPN.Protocol.Interop;
using HaloVPN.Shared;

namespace HaloVPN.Protocol.Tests;

public sealed class NativeSessionTests
{
    [Fact]
    public void NativeHandshakeAndEncryptedPingPongRoundTrip()
    {
        using var pair = EstablishedPair.Create();
        var ping = Encrypt(pair.Client, "ping"u8);
        Assert.False(Contains(ping, "ping"u8));
        Assert.Equal("ping"u8.ToArray(), Decrypt(pair.Server, ping));
        var pong = Encrypt(pair.Server, "pong"u8);
        Assert.Equal("pong"u8.ToArray(), Decrypt(pair.Client, pong));
    }

    [Fact]
    public void TamperedCiphertextAndOuterHeaderAreRejectedWithoutConsumingPacket()
    {
        using var pair = EstablishedPair.Create();
        var packet = Encrypt(pair.Client, "ping"u8);
        var tamperedCiphertext = (byte[])packet.Clone();
        tamperedCiphertext[^1] ^= 1;
        Assert.Equal(ProtocolErrorCode.AuthenticationFailed, TryDecrypt(pair.Server, tamperedCiphertext).ErrorCode);

        var tamperedHeader = (byte[])packet.Clone();
        BinaryPrimitives.WriteUInt64BigEndian(tamperedHeader.AsSpan(14), 1);
        Assert.Equal(ProtocolErrorCode.AuthenticationFailed, TryDecrypt(pair.Server, tamperedHeader).ErrorCode);

        Assert.Equal("ping"u8.ToArray(), Decrypt(pair.Server, packet));
    }

    [Fact]
    public void ReplayIsRejectedAndOutOfOrderInsideWindowIsAccepted()
    {
        using var pair = EstablishedPair.Create();
        var first = Encrypt(pair.Client, [0]);
        var second = Encrypt(pair.Client, [1]);

        Assert.Equal(new byte[] { 1 }, Decrypt(pair.Server, second));
        Assert.Equal(new byte[] { 0 }, Decrypt(pair.Server, first));
        Assert.Equal(ProtocolErrorCode.ReplayDetected, TryDecrypt(pair.Server, first).ErrorCode);
    }

    [Fact]
    public void PacketOlderThanReplayWindowIsRejected()
    {
        using var pair = EstablishedPair.Create();
        byte[]? first = null;
        byte[]? newest = null;
        for (var index = 0; index <= HaloProtocolConstants.ReplayWindowSize; index++)
        {
            var packet = Encrypt(pair.Client, [checked((byte)(index & 0xFF))]);
            first ??= packet;
            newest = packet;
        }

        Assert.NotNull(newest);
        _ = Decrypt(pair.Server, newest);
        Assert.NotNull(first);
        Assert.Equal(ProtocolErrorCode.ReplayDetected, TryDecrypt(pair.Server, first).ErrorCode);
    }

    [Fact]
    public void PacketCounterBoundaryRequiresRekey()
    {
        using var pair = EstablishedPair.Create();
        var packet = Encrypt(pair.Client, "x"u8);
        BinaryPrimitives.WriteUInt64BigEndian(packet.AsSpan(14), HaloProtocolConstants.SessionMessageLimit);

        Assert.Equal(ProtocolErrorCode.KeyLimitReached, TryDecrypt(pair.Server, packet).ErrorCode);
    }

    [Fact]
    public void AuthenticatedKeepAliveRejectsTamperingAndReplay()
    {
        using var pair = EstablishedPair.Create();
        var writer = new ArrayBufferWriter<byte>();
        Assert.True(pair.Client.WriteKeepAlive(writer).Success);
        var packet = writer.WrittenSpan.ToArray();
        var tampered = (byte[])packet.Clone();
        tampered[^1] ^= 1;
        Assert.Equal(ProtocolErrorCode.AuthenticationFailed, TryDecrypt(pair.Server, tampered).ErrorCode);
        Assert.True(TryDecrypt(pair.Server, packet).Success);
        Assert.Equal(ProtocolErrorCode.ReplayDetected, TryDecrypt(pair.Server, packet).ErrorCode);
    }

    [Fact]
    public void SessionUseAfterDisposeThrows()
    {
        var pair = EstablishedPair.Create();
        pair.Client.Dispose();
        Assert.Throws<ObjectDisposedException>(() => pair.Client.Encrypt("x"u8, new ArrayBufferWriter<byte>()));
        pair.Dispose();
    }

    [Fact]
    public void WrongClientStaticKeyIsRejected()
    {
        var clientKeys = NativeProtocolLibrary.GenerateKeyPair();
        var serverKeys = NativeProtocolLibrary.GenerateKeyPair();
        var wrongKeys = NativeProtocolLibrary.GenerateKeyPair();
        try
        {
            using var client = NativeProtocolSession.CreateClient(clientKeys.PrivateKey, serverKeys.PublicKey, 99);
            using var server = NativeProtocolSession.CreateServer(serverKeys.PrivateKey, wrongKeys.PublicKey);
            var initial = new ArrayBufferWriter<byte>();
            Assert.True(client.WriteHandshake(initial).Success);
            var result = server.ReadHandshake(initial.WrittenSpan, new ArrayBufferWriter<byte>());
            Assert.False(result.Success);
            Assert.Equal(ProtocolErrorCode.AuthenticationFailed, result.ErrorCode);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(clientKeys.PrivateKey);
            CryptographicOperations.ZeroMemory(serverKeys.PrivateKey);
            CryptographicOperations.ZeroMemory(wrongKeys.PrivateKey);
        }
    }

    private static byte[] Encrypt(NativeProtocolSession session, ReadOnlySpan<byte> plaintext)
    {
        var writer = new ArrayBufferWriter<byte>();
        var result = session.Encrypt(plaintext, writer);
        Assert.True(result.Success, result.ErrorCode.ToString());
        return writer.WrittenSpan.ToArray();
    }

    private static byte[] Decrypt(NativeProtocolSession session, ReadOnlySpan<byte> packet)
    {
        var writer = new ArrayBufferWriter<byte>();
        var result = session.Decrypt(packet, writer);
        Assert.True(result.Success, result.ErrorCode.ToString());
        return writer.WrittenSpan.ToArray();
    }

    private static ProtocolOperationResult TryDecrypt(NativeProtocolSession session, ReadOnlySpan<byte> packet) =>
        session.Decrypt(packet, new ArrayBufferWriter<byte>());

    private static bool Contains(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle)
    {
        for (var index = 0; index <= haystack.Length - needle.Length; index++)
        {
            if (haystack.Slice(index, needle.Length).SequenceEqual(needle))
            {
                return true;
            }
        }

        return false;
    }

    private sealed class EstablishedPair : IDisposable
    {
        private readonly byte[] _clientPrivate;
        private readonly byte[] _serverPrivate;

        private EstablishedPair(NativeProtocolSession client, NativeProtocolSession server, byte[] clientPrivate, byte[] serverPrivate)
        {
            Client = client;
            Server = server;
            _clientPrivate = clientPrivate;
            _serverPrivate = serverPrivate;
        }

        internal NativeProtocolSession Client { get; }

        internal NativeProtocolSession Server { get; }

        internal static EstablishedPair Create()
        {
            var clientKeys = NativeProtocolLibrary.GenerateKeyPair();
            var serverKeys = NativeProtocolLibrary.GenerateKeyPair();
            var client = NativeProtocolSession.CreateClient(clientKeys.PrivateKey, serverKeys.PublicKey, 7);
            var server = NativeProtocolSession.CreateServer(serverKeys.PrivateKey, clientKeys.PublicKey);
            var initial = new ArrayBufferWriter<byte>();
            Assert.True(client.WriteHandshake(initial).Success);
            var response = new ArrayBufferWriter<byte>();
            Assert.True(server.ReadHandshake(initial.WrittenSpan, response).Success);
            Assert.True(client.ReadHandshake(response.WrittenSpan, new ArrayBufferWriter<byte>()).Success);
            return new EstablishedPair(client, server, clientKeys.PrivateKey, serverKeys.PrivateKey);
        }

        public void Dispose()
        {
            Client.Dispose();
            Server.Dispose();
            CryptographicOperations.ZeroMemory(_clientPrivate);
            CryptographicOperations.ZeroMemory(_serverPrivate);
        }
    }
}

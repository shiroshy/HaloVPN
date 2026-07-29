using System.Buffers;
using System.Buffers.Binary;
using System.Net;
using HaloVPN.Infrastructure;
using HaloVPN.Node.Core;
using HaloVPN.Protocol.Interop;

namespace HaloVPN.PrivateMvp.Tests;

public sealed class NodeTests
{
    [Theory]
    [InlineData("169.254.169.254", DestinationPolicyResult.DeniedConfigured)]
    [InlineData("10.1.2.3", DestinationPolicyResult.DeniedConfigured)]
    [InlineData("100.64.1.1", DestinationPolicyResult.DeniedConfigured)]
    [InlineData("198.18.0.1", DestinationPolicyResult.DeniedConfigured)]
    [InlineData("8.8.8.8", DestinationPolicyResult.Allowed)]
    [InlineData("10.77.0.2", DestinationPolicyResult.DeniedTunnel)]
    [InlineData("203.0.113.9", DestinationPolicyResult.DeniedLocal)]
    public void DestinationPolicyProtectsSpecialTunnelAndLocalAddresses(string address, DestinationPolicyResult expected)
    {
        var policy = new DestinationPolicy(new DestinationPolicyOptions
        {
            TunnelSubnet = "10.77.0.0/24",
            LocalAddresses = [IPAddress.Parse("203.0.113.9")],
        });
        Assert.Equal(expected, policy.Evaluate(IPAddress.Parse(address)));
    }

    [Fact]
    public void DestinationAllowExceptionCannotOverrideAbsoluteDenials()
    {
        var policy = new DestinationPolicy(new DestinationPolicyOptions
        {
            TunnelSubnet = "10.77.0.0/24",
            AllowedDestinationCidrs = ["127.0.0.0/8", "224.0.0.0/4", "192.168.10.0/24"],
        });
        Assert.Equal(DestinationPolicyResult.DeniedAbsolute, policy.Evaluate(IPAddress.Loopback));
        Assert.Equal(DestinationPolicyResult.DeniedAbsolute, policy.Evaluate(IPAddress.Parse("224.0.0.1")));
        Assert.Equal(DestinationPolicyResult.Allowed, policy.Evaluate(IPAddress.Parse("192.168.10.8")));
    }

    [Fact]
    public async Task TwoAuthorizedClientsHandshakeAndExchangeIndependently()
    {
        var server = NativeProtocolLibrary.GenerateKeyPair();
        var clientOne = NativeProtocolLibrary.GenerateKeyPair();
        var clientTwo = NativeProtocolLibrary.GenerateKeyPair();
        try
        {
            var authorized = new[]
            {
                new AuthorizedDevice(Guid.NewGuid(), clientOne.PublicKey, IPAddress.Parse("10.77.0.2")),
                new AuthorizedDevice(Guid.NewGuid(), clientTwo.PublicKey, IPAddress.Parse("10.77.0.3")),
            };
            var repository = new ToggleRepository(authorized);
            var cache = new AuthorizationCache(repository, new AuthorizationCacheOptions(), TimeProvider.System);
            var registry = new NodeSessionRegistry(new NodeSessionOptions { MaximumActiveSessions = 2 });
            var coordinator = new NodeHandshakeCoordinator(cache, registry, TimeProvider.System);

            var handshakes = await Task.WhenAll(
                EstablishAsync(clientOne.PrivateKey, server.PublicKey, server.PrivateKey, coordinator, 10001),
                EstablishAsync(clientTwo.PrivateKey, server.PublicKey, server.PrivateKey, coordinator, 10002));
            var first = handshakes[0];
            var second = handshakes[1];
            Assert.Equal(2, registry.Count);
            Assert.NotEqual(first.Client.ConnectionId, second.Client.ConnectionId);
            AssertRoundTrip(first.Client, first.Server.Session.Protocol, "one"u8);
            AssertRoundTrip(second.Client, second.Server.Session.Protocol, "two"u8);
            AssertRoundTrip(first.Server.Session.Protocol, first.Client, "reply-one"u8);
            AssertRoundTrip(second.Server.Session.Protocol, second.Client, "reply-two"u8);
            registry.RemoveUnauthorized(new HashSet<Guid> { authorized[1].DeviceId });
            Assert.Equal(1, registry.Count);
            AssertRoundTrip(second.Client, second.Server.Session.Protocol, "still-active"u8);
            first.Client.Dispose();
            second.Client.Dispose();
            registry.DisposeAll();
        }
        finally
        {
            ZeroPair(server);
            ZeroPair(clientOne);
            ZeroPair(clientTwo);
        }
    }

    [Fact]
    public async Task AuthenticatedReconnectReplacesSameDeviceWithoutGrowingRegistry()
    {
        var server = NativeProtocolLibrary.GenerateKeyPair();
        var clientKeys = NativeProtocolLibrary.GenerateKeyPair();
        try
        {
            var device = new AuthorizedDevice(Guid.NewGuid(), clientKeys.PublicKey, IPAddress.Parse("10.77.0.2"));
            var cache = new AuthorizationCache(new ToggleRepository([device]), new AuthorizationCacheOptions(), TimeProvider.System);
            var registry = new NodeSessionRegistry(new NodeSessionOptions { MaximumActiveSessions = 2 });
            var coordinator = new NodeHandshakeCoordinator(cache, registry, TimeProvider.System);

            var first = await EstablishAsync(clientKeys.PrivateKey, server.PublicKey, server.PrivateKey, coordinator, 10001);
            var second = await EstablishAsync(clientKeys.PrivateKey, server.PublicKey, server.PrivateKey, coordinator, 10002);

            Assert.Equal(1, registry.Count);
            Assert.False(registry.TryGetByConnection(first.Client.ConnectionId, out _));
            Assert.True(registry.TryGetByConnection(second.Client.ConnectionId, out var active));
            Assert.Same(second.Server.Session, active);
            AssertRoundTrip(second.Client, second.Server.Session.Protocol, "reconnected"u8);

            first.Client.Dispose();
            second.Client.Dispose();
            registry.DisposeAll();
        }
        finally
        {
            ZeroPair(server);
            ZeroPair(clientKeys);
        }
    }

    [Theory]
    [InlineData("10.77.0.2", "8.8.8.8", PacketValidationResult.Accepted)]
    [InlineData("10.77.0.9", "8.8.8.8", PacketValidationResult.SourceSpoofed)]
    [InlineData("10.77.0.2", "10.77.0.3", PacketValidationResult.ClientToClient)]
    [InlineData("10.77.0.2", "224.0.0.1", PacketValidationResult.MulticastOrBroadcast)]
    public void ClientIpv4ValidationRejectsSpoofingAndClientToClient(string source, string destination, PacketValidationResult expected)
    {
        var active = new HashSet<uint> { Ipv4Subnet.ToUInt32(IPAddress.Parse("10.77.0.2")), Ipv4Subnet.ToUInt32(IPAddress.Parse("10.77.0.3")) };
        Assert.Equal(expected, Ipv4PacketValidator.ValidateFromClient(CreatePacket(source, destination), 1200, IPAddress.Parse("10.77.0.2"), active));
    }

    [Fact]
    public void MalformedAndUnknownTunDestinationAreDropped()
    {
        Assert.False(Ipv4PacketValidator.TryParse(new byte[19], 1200, out _));
        var active = new HashSet<uint> { Ipv4Subnet.ToUInt32(IPAddress.Parse("10.77.0.2")) };
        Assert.Equal(PacketValidationResult.UnknownDestination, Ipv4PacketValidator.ValidateFromTun(CreatePacket("8.8.8.8", "10.77.0.99"), 1200, active, out _));
    }

    [Fact]
    public async Task AuthorizationCacheKeepsStaleSessionsButFailsClosedForNewOnDatabaseFailure()
    {
        var repository = new ToggleRepository([new AuthorizedDevice(Guid.NewGuid(), new byte[32], IPAddress.Parse("10.77.0.2"))]);
        var time = new ManualTimeProvider(DateTimeOffset.UtcNow);
        var cache = new AuthorizationCache(repository, new AuthorizationCacheOptions { RefreshInterval = TimeSpan.FromSeconds(1), MaximumStaleAge = TimeSpan.FromMinutes(1) }, time);
        Assert.True((await cache.GetAsync(default)).CanAuthorizeNewSessions);
        repository.Throw = true;
        time.Advance(TimeSpan.FromSeconds(2));
        var stale = await cache.GetAsync(default);
        Assert.False(stale.CanAuthorizeNewSessions);
        Assert.Single(stale.Devices);
        time.Advance(TimeSpan.FromMinutes(2));
        Assert.Empty((await cache.GetAsync(default)).Devices);
    }

    [Fact]
    public async Task DeviceAbsentFromActiveAllowlistCannotHandshake()
    {
        var server = NativeProtocolLibrary.GenerateKeyPair();
        var revokedClient = NativeProtocolLibrary.GenerateKeyPair();
        try
        {
            var cache = new AuthorizationCache(new ToggleRepository([]), new AuthorizationCacheOptions(), TimeProvider.System);
            var registry = new NodeSessionRegistry(new NodeSessionOptions());
            var coordinator = new NodeHandshakeCoordinator(cache, registry, TimeProvider.System);
            using var client = NativeProtocolSession.CreateClient(revokedClient.PrivateKey, server.PublicKey);
            var initiation = new ArrayBufferWriter<byte>();
            Assert.True(client.WriteHandshake(initiation).Success);
            Assert.Null(await coordinator.TryAcceptAsync(initiation.WrittenMemory, new IPEndPoint(IPAddress.Loopback, 11000), server.PrivateKey, default));
            Assert.Equal(0, registry.Count);
        }
        finally
        {
            ZeroPair(server);
            ZeroPair(revokedClient);
        }
    }

    [Fact]
    public void PendingHandshakesAreBoundedGloballyAndPerSource()
    {
        var limiter = new NodeHandshakeRateLimiter(new NodeSessionOptions { MaximumPendingHandshakes = 2, MaximumPendingPerSource = 1 });
        Assert.True(limiter.TryAcquire(IPAddress.Parse("192.0.2.1"), DateTimeOffset.UtcNow, out var first));
        Assert.False(limiter.TryAcquire(IPAddress.Parse("192.0.2.1"), DateTimeOffset.UtcNow, out _));
        Assert.True(limiter.TryAcquire(IPAddress.Parse("192.0.2.2"), DateTimeOffset.UtcNow, out var second));
        Assert.False(limiter.TryAcquire(IPAddress.Parse("192.0.2.3"), DateTimeOffset.UtcNow, out _));
        first!.Dispose();
        second!.Dispose();
        Assert.True(limiter.TryAcquire(IPAddress.Parse("192.0.2.3"), DateTimeOffset.UtcNow.AddMinutes(1), out var reclaimed));
        reclaimed!.Dispose();
    }

    [Fact]
    public void DuplicateHandshakeCacheReturnsExactResponseWithoutAcceptingAlteredInitiation()
    {
        var pair = CreateHandshakePackets(77);
        try
        {
            var cache = new HandshakeResponseCache(new HandshakeResponseCacheOptions());
            var endpoint = new IPEndPoint(IPAddress.Parse("192.0.2.10"), 45000);
            var now = DateTimeOffset.UtcNow;
            Assert.True(cache.TryStore(endpoint, pair.Initiation, pair.Response, now));
            Assert.True(cache.TryGet(endpoint, pair.Initiation, now, out var cached));
            Assert.Equal(pair.Response, cached.ToArray());

            var altered = (byte[])pair.Initiation.Clone();
            altered[^1] ^= 1;
            Assert.False(cache.TryGet(endpoint, altered, now, out _));
            Assert.Equal(1, cache.Count);
        }
        finally
        {
            pair.Dispose();
        }
    }

    [Fact]
    public void HandshakeCacheEnforcesPerSourceGlobalAndTtlBounds()
    {
        var first = CreateHandshakePackets(101);
        var second = CreateHandshakePackets(102);
        var third = CreateHandshakePackets(103);
        try
        {
            var cache = new HandshakeResponseCache(new HandshakeResponseCacheOptions
            {
                MaximumEntries = 2,
                MaximumEntriesPerSource = 1,
                TimeToLive = TimeSpan.FromSeconds(1),
            });
            var now = DateTimeOffset.UtcNow;
            Assert.True(cache.TryStore(new IPEndPoint(IPAddress.Parse("192.0.2.1"), 4001), first.Initiation, first.Response, now));
            Assert.False(cache.TryStore(new IPEndPoint(IPAddress.Parse("192.0.2.1"), 4002), second.Initiation, second.Response, now));
            Assert.True(cache.TryStore(new IPEndPoint(IPAddress.Parse("192.0.2.2"), 4002), second.Initiation, second.Response, now));
            Assert.False(cache.TryStore(new IPEndPoint(IPAddress.Parse("192.0.2.3"), 4003), third.Initiation, third.Response, now));
            Assert.False(cache.TryGet(new IPEndPoint(IPAddress.Parse("192.0.2.1"), 4001), first.Initiation, now.AddSeconds(2), out _));
            Assert.Equal(0, cache.Count);
        }
        finally
        {
            first.Dispose();
            second.Dispose();
            third.Dispose();
        }
    }

    private static async Task<(NativeProtocolSession Client, AcceptedHandshake Server)> EstablishAsync(
        byte[] clientPrivate, byte[] serverPublic, byte[] serverPrivate, NodeHandshakeCoordinator coordinator, int port)
    {
        var client = NativeProtocolSession.CreateClient(clientPrivate, serverPublic);
        var initiation = new ArrayBufferWriter<byte>();
        Assert.True(client.WriteHandshake(initiation).Success);
        var accepted = await coordinator.TryAcceptAsync(initiation.WrittenMemory, new IPEndPoint(IPAddress.Loopback, port), serverPrivate, default);
        Assert.NotNull(accepted);
        Assert.True(client.ReadHandshake(accepted.Response.Span, new ArrayBufferWriter<byte>()).Success);
        return (client, accepted);
    }

    private static HandshakePackets CreateHandshakePackets(ulong connectionId)
    {
        var clientKeys = NativeProtocolLibrary.GenerateKeyPair();
        var serverKeys = NativeProtocolLibrary.GenerateKeyPair();
        using var client = NativeProtocolSession.CreateClient(clientKeys.PrivateKey, serverKeys.PublicKey, connectionId);
        using var server = NativeProtocolSession.CreateServer(serverKeys.PrivateKey, clientKeys.PublicKey);
        var initiation = new ArrayBufferWriter<byte>();
        Assert.True(client.WriteHandshake(initiation).Success);
        var response = new ArrayBufferWriter<byte>();
        Assert.True(server.ReadHandshake(initiation.WrittenSpan, response).Success);
        return new HandshakePackets(
            initiation.WrittenSpan.ToArray(),
            response.WrittenSpan.ToArray(),
            clientKeys.PrivateKey,
            serverKeys.PrivateKey);
    }

    private static void AssertRoundTrip(NativeProtocolSession sender, NativeProtocolSession receiver, ReadOnlySpan<byte> plaintext)
    {
        var packet = new ArrayBufferWriter<byte>();
        Assert.True(sender.Encrypt(plaintext, packet).Success);
        var output = new ArrayBufferWriter<byte>();
        Assert.True(receiver.Decrypt(packet.WrittenSpan, output).Success);
        Assert.True(plaintext.SequenceEqual(output.WrittenSpan));
    }

    private static byte[] CreatePacket(string source, string destination)
    {
        var packet = new byte[20];
        packet[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), 20);
        IPAddress.Parse(source).GetAddressBytes().CopyTo(packet, 12);
        IPAddress.Parse(destination).GetAddressBytes().CopyTo(packet, 16);
        return packet;
    }

    private static void ZeroPair((byte[] PrivateKey, byte[] PublicKey) pair)
    {
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(pair.PrivateKey);
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(pair.PublicKey);
    }

    private sealed class ToggleRepository(IReadOnlyList<AuthorizedDevice> devices) : INodeAuthorizationRepository
    {
        internal bool Throw { get; set; }
        public Task<IReadOnlyList<AuthorizedDevice>> GetAuthorizedDevicesAsync(int maximum, CancellationToken cancellationToken) =>
            Throw ? Task.FromException<IReadOnlyList<AuthorizedDevice>>(new IOException("test-only database outage")) : Task.FromResult(devices);
    }

    private sealed class ManualTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
        internal void Advance(TimeSpan value) => now += value;
    }

    private sealed record HandshakePackets(
        byte[] Initiation,
        byte[] Response,
        byte[] ClientPrivateKey,
        byte[] ServerPrivateKey) : IDisposable
    {
        public void Dispose()
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(ClientPrivateKey);
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(ServerPrivateKey);
        }
    }
}

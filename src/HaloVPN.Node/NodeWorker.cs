using System.Buffers;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using HaloVPN.Node.Core;
using HaloVPN.Infrastructure;
using HaloVPN.Platform.Linux;
using HaloVPN.Protocol.Abstractions;
using HaloVPN.Protocol.Interop;
using HaloVPN.Transport;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace HaloVPN.Node;

public sealed class NodeWorker(
    IOptions<NodeOptions> options,
    AuthorizationCache authorizationCache,
    NodeSessionRegistry sessions,
    NodeHandshakeRateLimiter handshakeLimiter,
    HandshakeResponseCache handshakeResponseCache,
    NodeHandshakeCoordinator handshakeCoordinator,
    TimeProvider timeProvider,
    ILogger<NodeWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var nodeOptions = Validate(options.Value);
        var tunnelSubnet = ParseTunnelSubnet(nodeOptions.TunnelGatewayCidr);
        var destinationPolicy = CreateDestinationPolicy(nodeOptions, tunnelSubnet);
        var privateKey = KeyMaterial.ReadPrivateKeyFile(nodeOptions.PrivateKeyPath);
        try
        {
            await using var carrier = new UdpCarrier(new IPEndPoint(IPAddress.Parse(nodeOptions.ListenAddress), nodeOptions.UdpPort));
            await using var tun = await LinuxTunDevice.CreateAsync(
                nodeOptions.TunName,
                nodeOptions.TunnelGatewayCidr,
                nodeOptions.Mtu,
                stoppingToken).ConfigureAwait(false);
            logger.LogInformation("Linux node listening endpoint={Endpoint} tun={TunName} mtu={Mtu}", carrier.LocalEndPoint, tun.Name, tun.Mtu);

            try
            {
                await Task.WhenAll(
                    RunUdpToTunAsync(carrier, tun, privateKey, tunnelSubnet, destinationPolicy, nodeOptions, stoppingToken),
                    RunTunToUdpAsync(carrier, tun, nodeOptions, stoppingToken),
                    RunMaintenanceAsync(nodeOptions, stoppingToken)).ConfigureAwait(false);
            }
            finally
            {
                sessions.DisposeAll();
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
        }
    }

    private async Task RunUdpToTunAsync(
        UdpCarrier carrier,
        ITunDevice tun,
        ReadOnlyMemory<byte> privateKey,
        Ipv4Subnet tunnelSubnet,
        DestinationPolicy destinationPolicy,
        NodeOptions nodeOptions,
        CancellationToken cancellationToken)
    {
        await foreach (var datagram in carrier.ReceiveAsync(cancellationToken).ConfigureAwait(false))
        {
            if (datagram.RemoteEndPoint is not IPEndPoint endpoint ||
                !HaloEnvelope.TryParse(datagram.Payload.Span, out var envelope, out _))
            {
                continue;
            }

            if (envelope.Header.MessageType == ProtocolMessageType.HandshakeInit)
            {
                if (handshakeResponseCache.TryGet(endpoint, datagram.Payload.Span, datagram.ReceivedAt, out var cachedResponse))
                {
                    await carrier.SendAsync(cachedResponse, endpoint, cancellationToken).ConfigureAwait(false);
                    continue;
                }

                if (!handshakeLimiter.TryAcquire(endpoint.Address, datagram.ReceivedAt, out var lease))
                {
                    continue;
                }

                using (lease)
                {
                    var accepted = await handshakeCoordinator.TryAcceptAsync(
                        datagram.Payload,
                        endpoint,
                        privateKey,
                        cancellationToken).ConfigureAwait(false);
                    if (accepted is not null)
                    {
                        _ = handshakeResponseCache.TryStore(endpoint, datagram.Payload.Span, accepted.Response.Span, datagram.ReceivedAt);
                        await carrier.SendAsync(accepted.Response, endpoint, cancellationToken).ConfigureAwait(false);
                        logger.LogInformation(
                            "Session established connection={ConnectionId:X16} device={DeviceId} endpoint={Endpoint}",
                            accepted.Session.Protocol.ConnectionId,
                            accepted.Session.Device.DeviceId,
                            endpoint);
                    }
                }

                continue;
            }

            if (!sessions.TryGetByConnection(envelope.Header.ConnectionId, out var session) || session is null ||
                !Equals(session.Endpoint, endpoint))
            {
                continue;
            }

            var plaintext = new ArrayBufferWriter<byte>(nodeOptions.Mtu);
            var result = session.Protocol.Decrypt(datagram.Payload.Span, plaintext);
            if (!result.Success)
            {
                logger.LogDebug("Datagram rejected connection={ConnectionId:X16} code={Code}", envelope.Header.ConnectionId, result.ErrorCode);
                continue;
            }

            session.Touch(timeProvider.GetUtcNow());
            if (envelope.Header.MessageType == ProtocolMessageType.KeepAlive)
            {
                var reply = new ArrayBufferWriter<byte>(128);
                var replyResult = session.Protocol.WriteKeepAlive(reply);
                if (replyResult.Success)
                {
                    await carrier.SendAsync(reply.WrittenMemory, endpoint, cancellationToken).ConfigureAwait(false);
                }

                continue;
            }

            if (envelope.Header.MessageType != ProtocolMessageType.Data)
            {
                continue;
            }

            var validation = Ipv4PacketValidator.ValidateFromClient(
                plaintext.WrittenSpan,
                nodeOptions.Mtu,
                session.Device.AssignedTunnelIp,
                sessions.ActiveTunnelAddresses(),
                tunnelSubnet);
            if (validation != PacketValidationResult.Accepted)
            {
                logger.LogWarning("Client packet rejected connection={ConnectionId:X16} code={Code}", envelope.Header.ConnectionId, validation);
                continue;
            }

            _ = Ipv4PacketValidator.TryParse(plaintext.WrittenSpan, nodeOptions.Mtu, out var packetInfo);
            var destinationResult = destinationPolicy.Evaluate(packetInfo.Destination);
            if (destinationResult != DestinationPolicyResult.Allowed)
            {
                logger.LogWarning("Client packet rejected connection={ConnectionId:X16} code={Code}", envelope.Header.ConnectionId, destinationResult);
                continue;
            }

            await tun.WriteAsync(plaintext.WrittenMemory, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task RunTunToUdpAsync(
        UdpCarrier carrier,
        ITunDevice tun,
        NodeOptions nodeOptions,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[nodeOptions.Mtu];
        while (!cancellationToken.IsCancellationRequested)
        {
            var length = await tun.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (length <= 0)
            {
                continue;
            }

            var activeAddresses = sessions.ActiveTunnelAddresses();
            var validation = Ipv4PacketValidator.ValidateFromTun(buffer.AsSpan(0, length), nodeOptions.Mtu, activeAddresses, out var destination);
            if (validation != PacketValidationResult.Accepted || !sessions.TryGetByTunnelAddress(destination, out var session) || session is null)
            {
                continue;
            }

            var encrypted = new ArrayBufferWriter<byte>(1400);
            var result = session.Protocol.Encrypt(buffer.AsSpan(0, length), encrypted);
            if (!result.Success)
            {
                logger.LogDebug("TUN packet encryption rejected connection={ConnectionId:X16} code={Code}", session.Protocol.ConnectionId, result.ErrorCode);
                continue;
            }

            session.Touch(timeProvider.GetUtcNow());
            await carrier.SendAsync(encrypted.WrittenMemory, session.Endpoint, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task RunMaintenanceAsync(NodeOptions nodeOptions, CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(nodeOptions.AuthorizationRefreshInterval, timeProvider);
        while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
        {
            var snapshot = await authorizationCache.GetAsync(cancellationToken).ConfigureAwait(false);
            if (snapshot.CanAuthorizeNewSessions)
            {
                sessions.RemoveUnauthorized(snapshot.Devices.Select(value => value.DeviceId).ToHashSet());
            }

            sessions.RemoveIdle(timeProvider.GetUtcNow());
        }
    }

    private static NodeOptions Validate(NodeOptions value)
    {
        if (value.Mtu is < 576 or > 1200 || value.MaximumActiveSessions is < 2 or > 256 ||
            value.MaximumPendingHandshakes is < 1 or > 1024 || value.MaximumPendingPerSource is < 1 or > 64 ||
            value.MaximumCachedDevices < value.MaximumActiveSessions || value.AuthorizationRefreshInterval <= TimeSpan.Zero)
        {
            throw new InvalidOperationException("Node configuration is outside supported Private MVP bounds.");
        }

        return value;
    }

    private static Ipv4Subnet ParseTunnelSubnet(string gatewayCidr)
    {
        var separator = gatewayCidr.LastIndexOf('/');
        if (separator <= 0 || !int.TryParse(gatewayCidr[(separator + 1)..], out var prefix))
        {
            throw new InvalidOperationException("Node tunnel gateway must be an IPv4 CIDR.");
        }

        var address = IPAddress.Parse(gatewayCidr[..separator]);
        var mask = prefix == 0 ? 0 : uint.MaxValue << (32 - prefix);
        var network = Ipv4Subnet.ToUInt32(address) & mask;
        return Ipv4Subnet.Parse($"{Ipv4Subnet.FromUInt32(network)}/{prefix}");
    }

    private static DestinationPolicy CreateDestinationPolicy(NodeOptions options, Ipv4Subnet tunnelSubnet)
    {
        var localAddresses = NetworkInterface.GetAllNetworkInterfaces()
            .SelectMany(value => value.GetIPProperties().UnicastAddresses)
            .Select(value => value.Address)
            .Where(value => value.AddressFamily == AddressFamily.InterNetwork)
            .ToArray();
        return new DestinationPolicy(new DestinationPolicyOptions
        {
            TunnelSubnet = $"{Ipv4Subnet.FromUInt32(tunnelSubnet.Network)}/{tunnelSubnet.PrefixLength}",
            DeniedDestinationCidrs = options.DeniedDestinationCidrs,
            AllowedDestinationCidrs = options.AllowedDestinationCidrs,
            LocalAddresses = localAddresses,
        });
    }
}

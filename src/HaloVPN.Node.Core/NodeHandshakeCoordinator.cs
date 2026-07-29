using System.Buffers;
using System.Net;
using HaloVPN.Infrastructure;
using HaloVPN.Protocol.Abstractions;
using HaloVPN.Protocol.Interop;

namespace HaloVPN.Node.Core;

public sealed record AcceptedHandshake(NodeSession Session, ReadOnlyMemory<byte> Response);

public sealed class NodeHandshakeCoordinator(
    AuthorizationCache authorizationCache,
    NodeSessionRegistry sessions,
    TimeProvider timeProvider)
{
    public async Task<AcceptedHandshake?> TryAcceptAsync(
        ReadOnlyMemory<byte> datagram,
        IPEndPoint endpoint,
        ReadOnlyMemory<byte> serverPrivateKey,
        CancellationToken cancellationToken)
    {
        if (!HaloEnvelope.TryParse(datagram.Span, out var envelope, out _) ||
            envelope.Header.MessageType != ProtocolMessageType.HandshakeInit)
        {
            return null;
        }

        var authorization = await authorizationCache.GetAsync(cancellationToken).ConfigureAwait(false);
        if (!authorization.CanAuthorizeNewSessions)
        {
            return null;
        }

        foreach (var device in authorization.Devices)
        {
            var candidate = NativeProtocolSession.CreateServer(serverPrivateKey.Span, device.NoisePublicKey);
            var response = new ArrayBufferWriter<byte>(512);
            var result = candidate.ReadHandshake(datagram.Span, response);
            if (!result.Success)
            {
                candidate.Dispose();
                continue;
            }

            var session = new NodeSession(device, candidate, endpoint, timeProvider.GetUtcNow());
            if (!sessions.TryAdd(session))
            {
                session.Dispose();
                return null;
            }

            return new AcceptedHandshake(session, response.WrittenMemory.ToArray());
        }

        return null;
    }
}

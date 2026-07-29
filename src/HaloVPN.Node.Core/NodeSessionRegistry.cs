using System.Collections.ObjectModel;
using System.Net;
using HaloVPN.Infrastructure;
using HaloVPN.Protocol.Interop;

namespace HaloVPN.Node.Core;

public sealed record NodeSessionOptions
{
    public int MaximumActiveSessions { get; init; } = 16;
    public int MaximumPendingHandshakes { get; init; } = 32;
    public int MaximumPendingPerSource { get; init; } = 4;
    public int MaximumAttemptsPerSourceWindow { get; init; } = 12;
    public TimeSpan AttemptWindow { get; init; } = TimeSpan.FromSeconds(10);
    public TimeSpan IdleTimeout { get; init; } = TimeSpan.FromMinutes(3);
}

public sealed class NodeSession : IDisposable
{
    internal NodeSession(AuthorizedDevice device, NativeProtocolSession protocol, IPEndPoint endpoint, DateTimeOffset now)
    {
        Device = device;
        Protocol = protocol;
        Endpoint = endpoint;
        LastActivityAt = now;
    }

    public AuthorizedDevice Device { get; }
    public NativeProtocolSession Protocol { get; }
    public IPEndPoint Endpoint { get; }
    public DateTimeOffset LastActivityAt { get; private set; }
    public void Touch(DateTimeOffset now) => LastActivityAt = now;
    public void Dispose() => Protocol.Dispose();
}

public sealed class NodeSessionRegistry(NodeSessionOptions options)
{
    private readonly object _sync = new();
    private readonly Dictionary<ulong, NodeSession> _byConnection = [];
    private readonly Dictionary<uint, NodeSession> _byTunnelAddress = [];

    public int Count
    {
        get { lock (_sync) { return _byConnection.Count; } }
    }

    public bool TryAdd(NodeSession session)
    {
        NodeSession? replaced = null;
        lock (_sync)
        {
            var address = Ipv4Subnet.ToUInt32(session.Device.AssignedTunnelIp);
            if (_byConnection.ContainsKey(session.Protocol.ConnectionId))
            {
                return false;
            }

            if (_byTunnelAddress.TryGetValue(address, out var existing))
            {
                if (existing.Device.DeviceId != session.Device.DeviceId)
                {
                    return false;
                }

                _byConnection.Remove(existing.Protocol.ConnectionId);
                _byTunnelAddress.Remove(address);
                replaced = existing;
            }
            else if (_byConnection.Count >= options.MaximumActiveSessions)
            {
                return false;
            }

            _byConnection.Add(session.Protocol.ConnectionId, session);
            _byTunnelAddress.Add(address, session);
        }

        replaced?.Dispose();
        return true;
    }

    public bool TryGetByConnection(ulong connectionId, out NodeSession? session)
    {
        lock (_sync) { return _byConnection.TryGetValue(connectionId, out session); }
    }

    public bool TryGetByTunnelAddress(uint address, out NodeSession? session)
    {
        lock (_sync) { return _byTunnelAddress.TryGetValue(address, out session); }
    }

    public IReadOnlySet<uint> ActiveTunnelAddresses()
    {
        lock (_sync) { return new ReadOnlySet<uint>(_byTunnelAddress.Keys.ToHashSet()); }
    }

    public void RemoveUnauthorized(IReadOnlySet<Guid> activeDeviceIds)
    {
        List<NodeSession> removed = [];
        lock (_sync)
        {
            foreach (var pair in _byConnection.Where(pair => !activeDeviceIds.Contains(pair.Value.Device.DeviceId)).ToArray())
            {
                _byConnection.Remove(pair.Key);
                _byTunnelAddress.Remove(Ipv4Subnet.ToUInt32(pair.Value.Device.AssignedTunnelIp));
                removed.Add(pair.Value);
            }
        }

        foreach (var session in removed)
        {
            session.Dispose();
        }
    }

    public void RemoveIdle(DateTimeOffset now)
    {
        List<NodeSession> removed = [];
        lock (_sync)
        {
            foreach (var pair in _byConnection.Where(pair => now - pair.Value.LastActivityAt >= options.IdleTimeout).ToArray())
            {
                _byConnection.Remove(pair.Key);
                _byTunnelAddress.Remove(Ipv4Subnet.ToUInt32(pair.Value.Device.AssignedTunnelIp));
                removed.Add(pair.Value);
            }
        }

        foreach (var session in removed)
        {
            session.Dispose();
        }
    }

    public void DisposeAll()
    {
        NodeSession[] sessions;
        lock (_sync)
        {
            sessions = [.. _byConnection.Values];
            _byConnection.Clear();
            _byTunnelAddress.Clear();
        }

        foreach (var session in sessions)
        {
            session.Dispose();
        }
    }
}

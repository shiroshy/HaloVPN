namespace HaloVPN.Platform.Windows;

public enum VpnConnectionState
{
    Disconnected = 0,
    Connecting,
    Connected,
    Reconnecting,
    Disconnecting,
    Faulted,
}

public sealed class VpnConnectionStateMachine
{
    private readonly object _sync = new();
    private VpnConnectionState _state;

    public VpnConnectionState State
    {
        get { lock (_sync) { return _state; } }
    }

    public bool TryTransition(VpnConnectionState next)
    {
        lock (_sync)
        {
            if (!IsAllowed(_state, next))
            {
                return false;
            }

            _state = next;
            return true;
        }
    }

    private static bool IsAllowed(VpnConnectionState current, VpnConnectionState next) => (current, next) switch
    {
        (VpnConnectionState.Disconnected, VpnConnectionState.Connecting) => true,
        (VpnConnectionState.Connecting, VpnConnectionState.Connected or VpnConnectionState.Faulted or VpnConnectionState.Disconnecting) => true,
        (VpnConnectionState.Connected, VpnConnectionState.Reconnecting or VpnConnectionState.Disconnecting or VpnConnectionState.Faulted) => true,
        (VpnConnectionState.Reconnecting, VpnConnectionState.Connected or VpnConnectionState.Disconnecting or VpnConnectionState.Faulted) => true,
        (VpnConnectionState.Faulted, VpnConnectionState.Reconnecting or VpnConnectionState.Disconnecting or VpnConnectionState.Disconnected) => true,
        (VpnConnectionState.Disconnecting, VpnConnectionState.Disconnected) => true,
        _ => false,
    };
}

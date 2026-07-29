using System.Net;
using HaloVPN.Contracts;

namespace HaloVPN.Platform.Windows;

public sealed record NetworkCommand(string FileName, IReadOnlyList<string> Arguments);

public enum NetworkMutationKind
{
    Unknown = 0,
    TunnelAddress,
    TunnelInterface,
    TunnelMtu,
    NodeHostRoute,
    BootstrapHostRoute,
    FullTunnelRoute,
    Dns,
    Ipv6Guard,
}

public enum NetworkCommandPhase
{
    Apply = 0,
    Rollback,
}

public readonly record struct NetworkCommandContext(int MutationIndex, NetworkMutationKind MutationKind, NetworkCommandPhase Phase);

public sealed record ReversibleNetworkCommand(
    NetworkCommand Apply,
    NetworkCommand Rollback,
    NetworkMutationKind Kind = NetworkMutationKind.Unknown);

public sealed record WindowsNetworkPlan(IReadOnlyList<ReversibleNetworkCommand> Commands);

public sealed record WindowsGuardDescriptor(
    int Version,
    string AdapterName,
    string AssignedClientIpv4,
    string TunnelGateway,
    int TunnelPrefixLength,
    int Mtu,
    string NodeIpv4,
    int NodeUdpPort,
    IReadOnlyList<string> BootstrapIpv4Addresses,
    string OriginalGateway,
    int OriginalInterfaceIndex,
    int TunnelInterfaceIndex,
    IReadOnlyList<string> DnsServers)
{
    public const int CurrentVersion = 1;

    public void Validate()
    {
        if (Version != CurrentVersion || string.IsNullOrWhiteSpace(AdapterName) || AdapterName.Length > 64 ||
            AdapterName.Any(char.IsControl) || BootstrapIpv4Addresses is null || DnsServers is null ||
            Mtu is < 576 or > 1200 || TunnelPrefixLength is < 1 or > 30 ||
            NodeUdpPort is < 1 or > 65535 || OriginalInterfaceIndex <= 0 || TunnelInterfaceIndex <= 0 ||
            BootstrapIpv4Addresses.Count > 16 || DnsServers.Count is < 1 or > 8)
        {
            throw new InvalidDataException("Persistent network guard descriptor is invalid.");
        }

        EnsureUsableIpv4(AssignedClientIpv4);
        EnsureUsableIpv4(TunnelGateway);
        EnsureUsableIpv4(NodeIpv4);
        EnsureUsableIpv4(OriginalGateway);
        foreach (var address in BootstrapIpv4Addresses.Concat(DnsServers))
        {
            EnsureUsableIpv4(address);
        }

        if (BootstrapIpv4Addresses.Distinct(StringComparer.Ordinal).Count() != BootstrapIpv4Addresses.Count)
        {
            throw new InvalidDataException("Bootstrap addresses must be unique.");
        }
    }

    private static void EnsureUsableIpv4(string value)
    {
        if (!IPAddress.TryParse(value, out var parsed) || parsed.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork ||
            IPAddress.Any.Equals(parsed) || IPAddress.Loopback.Equals(parsed) || parsed.GetAddressBytes()[0] >= 224)
        {
            throw new InvalidDataException("Persistent network guard contains an invalid IPv4 address.");
        }
    }
}

public static class WindowsNetworkPlanBuilder
{
    public static WindowsNetworkPlan BuildRecoveryRollback(
        WindowsGuardDescriptor descriptor,
        bool tunnelInterfaceAvailable)
    {
        var plan = Build(descriptor);
        if (tunnelInterfaceAvailable)
        {
            return plan;
        }

        return new WindowsNetworkPlan(plan.Commands
            .Where(command => command.Kind is not NetworkMutationKind.TunnelAddress and
                not NetworkMutationKind.TunnelInterface and not NetworkMutationKind.TunnelMtu and
                not NetworkMutationKind.Dns)
            .ToArray());
    }

    public static WindowsNetworkPlan Build(
        VpnProfileResponse profile,
        IPAddress resolvedNodeAddress,
        IPAddress originalGateway,
        int originalInterfaceIndex,
        int tunnelInterfaceIndex,
        string adapterName = "HaloVPN")
    {
        ArgumentNullException.ThrowIfNull(profile);
        EnsureIpv4(resolvedNodeAddress, nameof(resolvedNodeAddress));
        EnsureIpv4(originalGateway, nameof(originalGateway));
        if (originalInterfaceIndex <= 0 || tunnelInterfaceIndex <= 0 || profile.Mtu is < 576 or > 1200)
        {
            throw new ArgumentOutOfRangeException(nameof(originalInterfaceIndex));
        }

        return Build(new WindowsGuardDescriptor(
            WindowsGuardDescriptor.CurrentVersion,
            adapterName,
            profile.AssignedClientIpv4,
            profile.TunnelGateway,
            profile.TunnelPrefixLength,
            profile.Mtu,
            resolvedNodeAddress.ToString(),
            profile.UdpPort,
            [],
            originalGateway.ToString(),
            originalInterfaceIndex,
            tunnelInterfaceIndex,
            profile.DnsServers));
    }

    public static WindowsNetworkPlan Build(WindowsGuardDescriptor descriptor)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        descriptor.Validate();
        var node = descriptor.NodeIpv4;
        var gateway = descriptor.OriginalGateway;
        var adapterName = descriptor.AdapterName;
        var commands = new List<ReversibleNetworkCommand>();
        commands.AddRange(TunnelInterface(descriptor.TunnelInterfaceIndex));
        commands.AddRange(
        [
            new(
                new NetworkCommand("netsh.exe", ["interface", "ipv4", "set", "address", $"name={adapterName}", "source=static", $"address={descriptor.AssignedClientIpv4}", $"mask={PrefixToMask(descriptor.TunnelPrefixLength)}", "gateway=none", "store=active"]),
                new NetworkCommand("netsh.exe", ["interface", "ipv4", "delete", "address", $"name={adapterName}", $"address={descriptor.AssignedClientIpv4}", "store=active"]),
                NetworkMutationKind.TunnelAddress),
            new(
                new NetworkCommand("netsh.exe", ["interface", "ipv4", "set", "subinterface", adapterName, $"mtu={descriptor.Mtu}", "store=active"]),
                new NetworkCommand("netsh.exe", ["interface", "ipv4", "set", "subinterface", adapterName, "mtu=1500", "store=active"]),
                NetworkMutationKind.TunnelMtu),
            Route("add", node, "255.255.255.255", gateway, descriptor.OriginalInterfaceIndex, NetworkMutationKind.NodeHostRoute),
        ]);

        foreach (var bootstrap in descriptor.BootstrapIpv4Addresses.Where(value => !string.Equals(value, node, StringComparison.Ordinal)))
        {
            commands.Add(Route("add", bootstrap, "255.255.255.255", gateway, descriptor.OriginalInterfaceIndex, NetworkMutationKind.BootstrapHostRoute));
        }

        // Wintun is a layer-3 interface. A synthetic next hop makes Windows wait
        // for neighbor resolution and no IPv4 packet reaches the Wintun ring.
        // The routes must therefore be on-link; the configured /24 address keeps
        // source-address selection pinned to the assigned tunnel address.
        commands.Add(TunnelRoute("0.0.0.0/1", descriptor.TunnelInterfaceIndex, "0.0.0.0"));
        commands.Add(TunnelRoute("128.0.0.0/1", descriptor.TunnelInterfaceIndex, "0.0.0.0"));

        var dnsServers = descriptor.DnsServers
            .Select(IPAddress.Parse)
            .Distinct()
            .ToArray();
        for (var index = 0; index < dnsServers.Length; index++)
        {
            var dns = dnsServers[index];
            EnsureIpv4(dns, nameof(descriptor));
            var applyArguments = index == 0
                ? new[] { "interface", "ipv4", "set", "dnsservers", $"name={adapterName}", "source=static", $"address={dns}", "validate=no" }
                : new[] { "interface", "ipv4", "add", "dnsservers", $"name={adapterName}", $"address={dns}", $"index={index + 1}", "validate=no" };
            commands.Add(new ReversibleNetworkCommand(
                new NetworkCommand("netsh.exe", applyArguments),
                new NetworkCommand("netsh.exe", ["interface", "ipv4", "delete", "dnsservers", $"name={adapterName}", $"address={dns}", "validate=no"]),
                NetworkMutationKind.Dns));
        }

        commands.Add(FirewallRule("HaloVPN IPv6 Block Out", "out"));
        commands.Add(FirewallRule("HaloVPN IPv6 Block In", "in"));
        return new WindowsNetworkPlan(commands);
    }

    private static ReversibleNetworkCommand Route(
        string action,
        string destination,
        string mask,
        string gateway,
        int interfaceIndex,
        NetworkMutationKind kind)
    {
        var apply = new NetworkCommand("route.exe", ["-p", action, destination, "mask", mask, gateway, "if", interfaceIndex.ToString(System.Globalization.CultureInfo.InvariantCulture), "metric", "5"]);
        var rollback = new NetworkCommand("route.exe", ["delete", destination, "mask", mask, gateway, "if", interfaceIndex.ToString(System.Globalization.CultureInfo.InvariantCulture)]);
        return new ReversibleNetworkCommand(apply, rollback, kind);
    }

    private static ReversibleNetworkCommand TunnelRoute(string destinationPrefix, int interfaceIndex, string gateway) => new(
        new NetworkCommand(
            "powershell.exe",
            [
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                $"New-NetRoute -DestinationPrefix '{destinationPrefix}' -InterfaceIndex {interfaceIndex} -NextHop '{gateway}' -RouteMetric 5 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null",
            ]),
        new NetworkCommand(
            "powershell.exe",
            [
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                $"$route = Get-NetRoute -DestinationPrefix '{destinationPrefix}' -InterfaceIndex {interfaceIndex} -ErrorAction SilentlyContinue | Where-Object NextHop -eq '{gateway}'; if ($null -ne $route) {{ $route | Remove-NetRoute -Confirm:$false -ErrorAction Stop }}; exit 0",
            ]),
        NetworkMutationKind.FullTunnelRoute);

    private static IReadOnlyList<ReversibleNetworkCommand> TunnelInterface(int interfaceIndex) =>
    [
        InterfaceSetting(interfaceIndex, "RouterDiscovery", "Disabled", "Enabled"),
        InterfaceSetting(interfaceIndex, "DadTransmits", "0", "3"),
        InterfaceSetting(interfaceIndex, "ManagedAddressConfiguration", "Disabled", "Enabled"),
        InterfaceSetting(interfaceIndex, "OtherStatefulConfiguration", "Disabled", "Enabled"),
    ];

    private static ReversibleNetworkCommand InterfaceSetting(
        int interfaceIndex,
        string parameter,
        string applyValue,
        string rollbackValue) => new(
        PowerShell($"Set-NetIPInterface -InterfaceIndex {interfaceIndex} -AddressFamily IPv4 -{parameter} {applyValue} -PolicyStore ActiveStore -ErrorAction Stop"),
        PowerShell($"Set-NetIPInterface -InterfaceIndex {interfaceIndex} -AddressFamily IPv4 -{parameter} {rollbackValue} -PolicyStore ActiveStore -ErrorAction Stop"),
        NetworkMutationKind.TunnelInterface);

    private static NetworkCommand PowerShell(string command) => new(
        "powershell.exe",
        ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command]);

    private static string PrefixToMask(int prefixLength)
    {
        var mask = uint.MaxValue << (32 - prefixLength);
        return string.Create(
            System.Globalization.CultureInfo.InvariantCulture,
            $"{mask >> 24}.{(mask >> 16) & 0xFF}.{(mask >> 8) & 0xFF}.{mask & 0xFF}");
    }

    private static ReversibleNetworkCommand FirewallRule(string name, string direction) => new(
        // Windows 10 rejects the otherwise valid zero-length IPv6 prefix in this
        // firewall context. The two /1 prefixes cover the complete IPv6 space.
        new NetworkCommand("netsh.exe", ["advfirewall", "firewall", "add", "rule", $"name={name}", $"dir={direction}", "action=block", "protocol=any", "remoteip=::/1,8000::/1"]),
        new NetworkCommand(
            "powershell.exe",
            [
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                $"$rule = Get-NetFirewallRule -DisplayName '{name}' -ErrorAction SilentlyContinue; if ($null -ne $rule) {{ Remove-NetFirewallRule -DisplayName '{name}' -ErrorAction Stop }}; exit 0",
            ]),
        NetworkMutationKind.Ipv6Guard);

    private static void EnsureIpv4(IPAddress value, string parameterName)
    {
        if (value.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
        {
            throw new ArgumentException("Only IPv4 is supported.", parameterName);
        }
    }

}

public interface INetworkCommandExecutor
{
    Task ExecuteAsync(NetworkCommand command, NetworkCommandContext context, CancellationToken cancellationToken);
}

public sealed class NetworkPlanApplyException(
    bool rollbackSucceeded,
    int mutationIndex,
    NetworkMutationKind mutationKind,
    Exception innerException)
    : InvalidOperationException("Persistent network guard could not be applied.", innerException)
{
    public bool RollbackSucceeded { get; } = rollbackSucceeded;
    public int MutationIndex { get; } = mutationIndex;
    public NetworkMutationKind MutationKind { get; } = mutationKind;
    public string DiagnosticCode { get; } = mutationKind switch
    {
        NetworkMutationKind.TunnelAddress => "TunnelAddressApplyFailed",
        NetworkMutationKind.TunnelInterface => "TunnelInterfaceApplyFailed",
        NetworkMutationKind.TunnelMtu => "TunnelMtuApplyFailed",
        NetworkMutationKind.NodeHostRoute => "NodeHostRouteFailed",
        NetworkMutationKind.BootstrapHostRoute => "BootstrapHostRouteFailed",
        NetworkMutationKind.FullTunnelRoute => "FullTunnelRouteFailed",
        NetworkMutationKind.Dns => "DnsApplyFailed",
        NetworkMutationKind.Ipv6Guard => "Ipv6GuardFailed",
        _ => "NetworkGuardApplyFailed",
    };
}

public sealed class NetworkPlanTransaction(INetworkCommandExecutor executor)
{
    public async Task ApplyAsync(WindowsNetworkPlan plan, CancellationToken cancellationToken)
    {
        var applied = new Stack<(int Index, ReversibleNetworkCommand Mutation)>();
        var currentIndex = -1;
        var currentKind = NetworkMutationKind.Unknown;
        try
        {
            for (var index = 0; index < plan.Commands.Count; index++)
            {
                var command = plan.Commands[index];
                currentIndex = index;
                currentKind = command.Kind;
                await executor.ExecuteAsync(
                    command.Apply,
                    new NetworkCommandContext(index, command.Kind, NetworkCommandPhase.Apply),
                    cancellationToken).ConfigureAwait(false);
                applied.Push((index, command));
            }
        }
        catch (Exception exception)
        {
            var rollbackFailures = 0;
            while (applied.TryPop(out var appliedMutation))
            {
                try
                {
                    await executor.ExecuteAsync(
                        appliedMutation.Mutation.Rollback,
                        new NetworkCommandContext(appliedMutation.Index, appliedMutation.Mutation.Kind, NetworkCommandPhase.Rollback),
                        CancellationToken.None).ConfigureAwait(false);
                }
                catch (Exception rollbackException) when (rollbackException is InvalidOperationException or IOException)
                {
                    rollbackFailures++;
                }
            }

            throw new NetworkPlanApplyException(rollbackFailures == 0, currentIndex, currentKind, exception);
        }
    }

    public async Task RollbackAsync(WindowsNetworkPlan plan, CancellationToken cancellationToken)
    {
        var failures = 0;
        for (var index = plan.Commands.Count - 1; index >= 0; index--)
        {
            var command = plan.Commands[index];
            try
            {
                await executor.ExecuteAsync(
                    command.Rollback,
                    new NetworkCommandContext(index, command.Kind, NetworkCommandPhase.Rollback),
                    cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is InvalidOperationException or IOException)
            {
                failures++;
            }
        }

        if (failures > 0)
        {
            throw new InvalidOperationException($"{failures} owned network mutations could not be rolled back.");
        }
    }
}

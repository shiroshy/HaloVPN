using System.Buffers.Binary;
using System.Net;
using System.Threading.Channels;
using HaloVPN.Contracts;
using HaloVPN.Platform.Windows;
using HaloVPN.WindowsService;
using Microsoft.Extensions.Logging.Abstractions;

namespace HaloVPN.Windows.Tests;

public sealed class WindowsLogicTests
{
    [Fact]
    public void RouteDnsAndIpv6PlanOwnsOnlySpecificMutations()
    {
        var plan = WindowsNetworkPlanBuilder.Build(Profile(), IPAddress.Parse("203.0.113.5"), IPAddress.Parse("192.168.1.1"), 7, 42);
        var applications = plan.Commands.Select(value => string.Join(' ', value.Apply.Arguments)).ToArray();
        Assert.Contains(applications, value => value.Contains("203.0.113.5 mask 255.255.255.255 192.168.1.1 if 7", StringComparison.Ordinal));
        Assert.Contains(applications, value => value.Contains("New-NetRoute -DestinationPrefix '0.0.0.0/1' -InterfaceIndex 42 -NextHop '0.0.0.0'", StringComparison.Ordinal));
        Assert.Contains(applications, value => value.Contains("New-NetRoute -DestinationPrefix '128.0.0.0/1' -InterfaceIndex 42 -NextHop '0.0.0.0'", StringComparison.Ordinal));
        Assert.Contains(applications, value => value.Contains("address=10.77.0.2 mask=255.255.255.0 gateway=none", StringComparison.Ordinal));
        Assert.Contains(applications, value => value.Contains("-RouterDiscovery Disabled", StringComparison.Ordinal));
        Assert.Contains(applications, value => value.Contains("-DadTransmits 0", StringComparison.Ordinal));
        Assert.DoesNotContain(applications, value => value.Contains("-NeighborUnreachabilityDetection", StringComparison.Ordinal));
        Assert.Contains(applications, value => value.Contains("-ManagedAddressConfiguration Disabled", StringComparison.Ordinal));
        Assert.Contains(applications, value => value.Contains("-OtherStatefulConfiguration Disabled", StringComparison.Ordinal));
        Assert.DoesNotContain(applications, value => value.Contains("-AutomaticMetric", StringComparison.Ordinal));
        Assert.DoesNotContain(applications, value => value.Contains("-InterfaceMetric", StringComparison.Ordinal));
        Assert.Contains(applications, value => value.Contains("dnsservers name=HaloVPN", StringComparison.Ordinal));
        Assert.Contains(applications, value => value.Contains("HaloVPN IPv6 Block Out", StringComparison.Ordinal));
        Assert.Contains(applications, value => value.Contains("remoteip=::/1,8000::/1", StringComparison.Ordinal));
        Assert.DoesNotContain(applications, value => value.Contains("remoteip=::/0", StringComparison.Ordinal));
        Assert.All(
            plan.Commands.Where(value => value.Kind == NetworkMutationKind.Ipv6Guard),
            value =>
            {
                Assert.Equal("powershell.exe", value.Rollback.FileName);
                Assert.Contains(value.Rollback.Arguments, argument => argument.Contains("Get-NetFirewallRule -DisplayName 'HaloVPN IPv6 Block", StringComparison.Ordinal));
                Assert.Contains(value.Rollback.Arguments, argument => argument.Contains("Remove-NetFirewallRule -DisplayName 'HaloVPN IPv6 Block", StringComparison.Ordinal));
            });
        Assert.All(plan.Commands, command => Assert.NotEmpty(command.Rollback.Arguments));
    }

    [Fact]
    public void WindowsClientAddressUsesConfiguredTunnelPrefix()
    {
        var descriptor = Descriptor(["198.51.100.7"]) with { TunnelPrefixLength = 24 };
        var addressMutation = WindowsNetworkPlanBuilder.Build(descriptor).Commands
            .Single(command => command.Kind == NetworkMutationKind.TunnelAddress);
        var arguments = string.Join(' ', addressMutation.Apply.Arguments);
        Assert.Contains("address=10.77.0.2 mask=255.255.255.0 gateway=none", arguments, StringComparison.Ordinal);
    }

    [Fact]
    public void GuardPlanUsesOnlyExactBootstrapExceptionsAndFullTunnelHalves()
    {
        var descriptor = Descriptor(["198.51.100.7", "198.51.100.8"]);
        var plan = WindowsNetworkPlanBuilder.Build(descriptor);
        var routes = plan.Commands
            .Select(value => string.Join(' ', value.Apply.Arguments)).ToArray();
        Assert.Contains(routes, value => value.Contains("198.51.100.7 mask 255.255.255.255", StringComparison.Ordinal));
        Assert.Contains(routes, value => value.Contains("198.51.100.8 mask 255.255.255.255", StringComparison.Ordinal));
        Assert.Contains(routes, value => value.Contains("New-NetRoute -DestinationPrefix '0.0.0.0/1'", StringComparison.Ordinal));
        Assert.Contains(routes, value => value.Contains("New-NetRoute -DestinationPrefix '128.0.0.0/1'", StringComparison.Ordinal));
        Assert.DoesNotContain(routes, value => value.Contains("mask 0.0.0.0", StringComparison.Ordinal));
    }

    [Fact]
    public void WindowsTenPlanDeduplicatesDnsAndUsesSupportedCommandSyntax()
    {
        var descriptor = Descriptor(["198.51.100.7"]) with
        {
            DnsServers = ["1.1.1.1", "1.1.1.1", "9.9.9.9"],
        };
        var plan = WindowsNetworkPlanBuilder.Build(descriptor);
        var dns = plan.Commands.Where(value => value.Kind == NetworkMutationKind.Dns).ToArray();
        Assert.Equal(2, dns.Length);
        Assert.Equal(["interface", "ipv4", "set", "dnsservers", "name=HaloVPN", "source=static", "address=1.1.1.1", "validate=no"], dns[0].Apply.Arguments);
        Assert.Equal(["interface", "ipv4", "add", "dnsservers", "name=HaloVPN", "address=9.9.9.9", "index=2", "validate=no"], dns[1].Apply.Arguments);
        Assert.All(plan.Commands.Where(value => value.Apply.FileName == "route.exe"), value => Assert.Equal("-p", value.Apply.Arguments[0]));
    }

    [Fact]
    public async Task FailingNetworkCommandCapturesExitStdoutStderrAndMutationContext()
    {
        var executor = new ProcessNetworkCommandExecutor(NullLogger<ProcessNetworkCommandExecutor>.Instance);
        var command = new NetworkCommand("cmd.exe", ["/d", "/c", "echo TEST-OUT & echo TEST-ERR 1>&2 & exit /b 7"]);
        var context = new NetworkCommandContext(6, NetworkMutationKind.Dns, NetworkCommandPhase.Apply);
        var exception = await Assert.ThrowsAsync<NetworkCommandFailedException>(() => executor.ExecuteAsync(command, context, default));
        Assert.Equal(7, exception.ExitCode);
        Assert.Contains("TEST-OUT", exception.StandardOutput, StringComparison.Ordinal);
        Assert.Contains("TEST-ERR", exception.StandardError, StringComparison.Ordinal);
        Assert.Equal(context, exception.Context);
    }

    [Fact]
    public async Task AdapterAppearanceWaitRetriesWithinBound()
    {
        var probes = 0;
        await InterfaceAppearanceWaiter.WaitAsync(
            () => Interlocked.Increment(ref probes) >= 3,
            TimeSpan.FromSeconds(1),
            TimeSpan.FromMilliseconds(10),
            TimeProvider.System,
            default);
        Assert.Equal(3, probes);
    }

    [Fact]
    public void GuardPlanContainsNoDuplicateApplyCommands()
    {
        var descriptor = Descriptor(["203.0.113.5", "198.51.100.7"]) with
        {
            DnsServers = ["1.1.1.1", "1.1.1.1"],
        };
        var commands = WindowsNetworkPlanBuilder.Build(descriptor).Commands
            .Select(value => $"{value.Apply.FileName}|{string.Join('|', value.Apply.Arguments)}")
            .ToArray();
        Assert.Equal(commands.Length, commands.Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public void RecoveryRollbackWithoutAdapterKeepsOnlyExternallyOwnedCleanup()
    {
        var plan = WindowsNetworkPlanBuilder.BuildRecoveryRollback(Descriptor(["198.51.100.7"]), tunnelInterfaceAvailable: false);
        Assert.DoesNotContain(plan.Commands, command => command.Kind is NetworkMutationKind.TunnelAddress or NetworkMutationKind.TunnelInterface or NetworkMutationKind.TunnelMtu or NetworkMutationKind.Dns);
        Assert.Contains(plan.Commands, command => command.Kind == NetworkMutationKind.NodeHostRoute);
        Assert.Contains(plan.Commands, command => command.Kind == NetworkMutationKind.FullTunnelRoute);
        Assert.Equal(2, plan.Commands.Count(command => command.Kind == NetworkMutationKind.Ipv6Guard));
    }

    [Fact]
    public void ServiceUpdateScriptPreservesProductionConfiguration()
    {
        var repositoryRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", ".."));
        var script = File.ReadAllText(Path.Combine(repositoryRoot, "scripts", "update-windows-service.ps1"));
        Assert.Contains("appsettings*.json", script, StringComparison.Ordinal);
        Assert.Contains("Get-FileHash", script, StringComparison.Ordinal);
        Assert.Contains("Production configuration changed during update", script, StringComparison.Ordinal);
        Assert.DoesNotContain("Remove-Item -LiteralPath $productionConfig", script, StringComparison.Ordinal);
    }

    [Fact]
    public void WindowsPreflightIsReadOnlyAndContainsNoMachineSpecificSid()
    {
        var repositoryRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", ".."));
        var script = File.ReadAllText(Path.Combine(repositoryRoot, "scripts", "preflight-windows.ps1"));
        Assert.DoesNotContain("Start-Service", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Stop-Service", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Set-Net", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("New-Net", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Remove-Net", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotMatch(@"S-1-5-21-\d+", script);
        Assert.Contains("No system state was changed", script, StringComparison.Ordinal);
    }

    [Fact]
    public void TesterInstallerGeneratesLocalConfigurationWithoutBundledIdentity()
    {
        var repositoryRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", ".."));
        var script = File.ReadAllText(Path.Combine(repositoryRoot, "scripts", "install-windows-test-bundle.ps1"));
        Assert.Contains("Resolve-InteractiveUserSid", script, StringComparison.Ordinal);
        Assert.Contains("Get-AuthenticodeSignature", script, StringComparison.Ordinal);
        Assert.Contains("Device private key will be generated locally", script, StringComparison.Ordinal);
        Assert.DoesNotMatch(@"S-1-5-21-\d+", script);
        Assert.DoesNotContain("ControlPlaneUrl", script, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TypedGuardJournalRoundTripsAndRejectsCommandPayload()
    {
        var directory = Path.Combine(Path.GetTempPath(), "halovpn-guard-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "guard.json");
        try
        {
            var journal = new WindowsGuardJournal(path);
            await journal.SaveAsync(Descriptor(["198.51.100.7"]), default);
            var json = await File.ReadAllTextAsync(path);
            Assert.DoesNotContain("fileName", json, StringComparison.OrdinalIgnoreCase);
            Assert.NotNull(await journal.LoadAsync(default));

            await File.WriteAllTextAsync(path, "{\"version\":1,\"fileName\":\"cmd.exe\",\"arguments\":[\"/c\",\"test\"]}");
            await Assert.ThrowsAsync<InvalidDataException>(() => journal.LoadAsync(default));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task HandshakeRetransmissionReusesExactInitiationAfterLoss()
    {
        var responses = Channel.CreateBounded<ReadOnlyMemory<byte>>(4);
        var sent = new List<byte[]>();
        var initiation = new byte[] { 1, 2, 3, 4 };
        var expected = new byte[] { 9, 8, 7 };
        var retransmitter = new HandshakeRetransmitter(new HandshakeRetransmissionOptions
        {
            Attempts = 4,
            InitialDelay = TimeSpan.FromMilliseconds(20),
            MaximumDelay = TimeSpan.FromMilliseconds(40),
            TotalTimeout = TimeSpan.FromSeconds(1),
        }, TimeProvider.System);

        ValueTask Send(ReadOnlyMemory<byte> payload, CancellationToken _)
        {
            sent.Add(payload.ToArray());
            if (sent.Count == 2)
            {
                responses.Writer.TryWrite(expected);
            }

            return ValueTask.CompletedTask;
        }

        var received = await retransmitter.ExchangeAsync(
            initiation,
            Send,
            token => responses.Reader.ReadAsync(token),
            value => value.Span.SequenceEqual(expected),
            default);
        Assert.Equal(expected, received.ToArray());
        Assert.Equal(2, sent.Count);
        Assert.All(sent, value => Assert.Equal(initiation, value));
    }

    [Fact]
    public async Task HandshakeRetransmissionCancellationStopsBoundedReceive()
    {
        var responses = Channel.CreateBounded<ReadOnlyMemory<byte>>(1);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(60));
        var sends = 0;
        var retransmitter = new HandshakeRetransmitter(new HandshakeRetransmissionOptions
        {
            Attempts = 4,
            InitialDelay = TimeSpan.FromMilliseconds(20),
            MaximumDelay = TimeSpan.FromMilliseconds(40),
            TotalTimeout = TimeSpan.FromSeconds(1),
        }, TimeProvider.System);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => retransmitter.ExchangeAsync(
            new byte[] { 1 },
            (_, _) => { Interlocked.Increment(ref sends); return ValueTask.CompletedTask; },
            token => responses.Reader.ReadAsync(token),
            _ => true,
            cancellation.Token));
        Assert.InRange(sends, 1, 4);
    }

    [Fact]
    public void LivenessSendsOnlyAfterOutboundIdleAndTimesOutWithoutAuthenticatedInbound()
    {
        var time = new ManualTimeProvider(DateTimeOffset.UtcNow);
        var tracker = new TunnelLivenessTracker(time, TimeSpan.FromSeconds(20), TimeSpan.FromSeconds(60));
        time.Advance(TimeSpan.FromSeconds(19));
        Assert.False(tracker.ShouldSendKeepAlive());
        tracker.MarkOutbound();
        time.Advance(TimeSpan.FromSeconds(19));
        Assert.False(tracker.ShouldSendKeepAlive());
        time.Advance(TimeSpan.FromSeconds(1));
        Assert.True(tracker.ShouldSendKeepAlive());
        tracker.MarkInbound();
        time.Advance(TimeSpan.FromSeconds(59));
        Assert.False(tracker.HasTimedOut());
        time.Advance(TimeSpan.FromSeconds(1));
        Assert.True(tracker.HasTimedOut());
    }

    [Fact]
    public async Task PartialNetworkPlanFailureRollsBackOnlyAppliedCommandsInReverseOrder()
    {
        var executor = new RecordingExecutor(3);
        var plan = new WindowsNetworkPlan(
        [
            Pair("one"), Pair("two"), Pair("three", NetworkMutationKind.Dns), Pair("four"),
        ]);
        var exception = await Assert.ThrowsAsync<NetworkPlanApplyException>(() => new NetworkPlanTransaction(executor).ApplyAsync(plan, default));
        Assert.True(exception.RollbackSucceeded);
        Assert.Equal("DnsApplyFailed", exception.DiagnosticCode);
        Assert.Equal(2, exception.MutationIndex);
        Assert.Equal(["apply-one", "apply-two", "apply-three", "rollback-two", "rollback-one"], executor.Calls);
    }

    [Fact]
    public void ReconnectStateMachineRejectsInvalidTransitions()
    {
        var state = new VpnConnectionStateMachine();
        Assert.False(state.TryTransition(VpnConnectionState.Connected));
        Assert.True(state.TryTransition(VpnConnectionState.Connecting));
        Assert.True(state.TryTransition(VpnConnectionState.Connected));
        Assert.True(state.TryTransition(VpnConnectionState.Reconnecting));
        Assert.True(state.TryTransition(VpnConnectionState.Connected));
        Assert.True(state.TryTransition(VpnConnectionState.Disconnecting));
        Assert.True(state.TryTransition(VpnConnectionState.Disconnected));
    }

    [Fact]
    public async Task IpcRejectsUnknownTypeAndOversizedLength()
    {
        await using var unknown = new MemoryStream();
        var body = "{\"version\":1,\"type\":999,\"profile\":null}"u8.ToArray();
        var header = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(header, body.Length);
        await unknown.WriteAsync(header);
        await unknown.WriteAsync(body);
        unknown.Position = 0;
        await Assert.ThrowsAsync<InvalidDataException>(() => IpcProtocol.ReadAsync(unknown, default));

        await using var oversized = new MemoryStream();
        BinaryPrimitives.WriteInt32BigEndian(header, IpcProtocol.MaximumMessageSize + 1);
        await oversized.WriteAsync(header);
        oversized.Position = 0;
        await Assert.ThrowsAsync<InvalidDataException>(() => IpcProtocol.ReadAsync(oversized, default));

        await using var missingBootstrap = new MemoryStream();
        await Assert.ThrowsAsync<InvalidDataException>(() => IpcProtocol.WriteAsync(
            missingBootstrap,
            new IpcRequest(IpcProtocol.Version, IpcMessageType.Connect, Profile()),
            default));

        await using var invalidBootstrap = new MemoryStream();
        await Assert.ThrowsAsync<InvalidDataException>(() => IpcProtocol.WriteAsync(
            invalidBootstrap,
            new IpcRequest(IpcProtocol.Version, IpcMessageType.Connect, Profile(), ["127.0.0.1"]),
            default));
    }

    [Fact]
    public void NamedPipeAuthorizationAllowsConfiguredUserAndAdministratorsOnly()
    {
        Assert.True(NamedPipeAuthorization.IsAllowed("S-1-5-21-1", "S-1-5-21-1", false));
        Assert.True(NamedPipeAuthorization.IsAllowed("S-1-5-21-1", "S-1-5-21-2", true));
        Assert.False(NamedPipeAuthorization.IsAllowed("S-1-5-21-1", "S-1-5-21-2", false));
        Assert.False(NamedPipeAuthorization.IsAllowed(string.Empty, "S-1-5-21-1", true));
    }

    [Fact]
    public async Task RefreshTokenStoreRoundTripsThroughCurrentUserDpapi()
    {
        var directory = Path.Combine(Path.GetTempPath(), "halovpn-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "token.bin");
        try
        {
            var store = new DpapiTokenStore(path);
            await store.SaveAsync("test-only-refresh-token", default);
            Assert.Equal("test-only-refresh-token", await store.LoadAsync(default));
            store.Delete();
            Assert.Null(await store.LoadAsync(default));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static VpnProfileResponse Profile() => new(
        Guid.NewGuid(), "Astana-1", "vpn.example.test", 45000, Convert.ToBase64String(new byte[32]),
        "10.77.0.2", "10.77.0.1", 24, 1200, ["1.1.1.1", "9.9.9.9"], 0);

    private static WindowsGuardDescriptor Descriptor(IReadOnlyList<string> bootstrap) => new(
        WindowsGuardDescriptor.CurrentVersion,
        "HaloVPN",
        "10.77.0.2",
        "10.77.0.1",
        24,
        1200,
        "203.0.113.5",
        45000,
        bootstrap,
        "192.168.1.1",
        7,
        42,
        ["1.1.1.1", "9.9.9.9"]);

    private static ReversibleNetworkCommand Pair(string name, NetworkMutationKind kind = NetworkMutationKind.Unknown) => new(
        new NetworkCommand("test", [$"apply-{name}"]), new NetworkCommand("test", [$"rollback-{name}"]), kind);

    private sealed class RecordingExecutor(int failAt) : INetworkCommandExecutor
    {
        private int _count;
        internal List<string> Calls { get; } = [];
        public Task ExecuteAsync(NetworkCommand command, NetworkCommandContext context, CancellationToken cancellationToken)
        {
            Calls.Add(command.Arguments[0]);
            _count++;
            return _count == failAt ? Task.FromException(new InvalidOperationException("test failure")) : Task.CompletedTask;
        }
    }

    private sealed class ManualTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
        internal void Advance(TimeSpan value) => now += value;
    }
}

using System.Buffers;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using HaloVPN.Contracts;
using HaloVPN.Platform.Windows;
using HaloVPN.Protocol.Abstractions;
using HaloVPN.Protocol.Interop;
using HaloVPN.Transport;
using Microsoft.Extensions.Options;

namespace HaloVPN.WindowsService;

public sealed record WindowsVpnServiceOptions
{
    public string PipeName { get; init; } = "HaloVPN.Service.v1";
    public string AllowedUserSid { get; init; } = string.Empty;
    public string DeviceKeyPath { get; init; } = @"C:\ProgramData\HaloVPN\device-key.json";
    public string WintunDllPath { get; init; } = @"C:\Program Files\HaloVPN\wintun.dll";
    public string AdapterName { get; init; } = "HaloVPN";
    public string NetworkJournalPath { get; init; } = @"C:\ProgramData\HaloVPN\network-plan.json";
    public int HandshakeAttempts { get; init; } = 4;
    public TimeSpan HandshakeInitialDelay { get; init; } = TimeSpan.FromMilliseconds(500);
    public TimeSpan HandshakeMaximumDelay { get; init; } = TimeSpan.FromSeconds(2);
    public TimeSpan HandshakeTimeout { get; init; } = TimeSpan.FromSeconds(10);
    public TimeSpan KeepAliveInterval { get; init; } = TimeSpan.FromSeconds(20);
    public TimeSpan LivenessTimeout { get; init; } = TimeSpan.FromSeconds(65);
}

public sealed class VpnServiceOperationException(string diagnosticCode, Exception innerException)
    : InvalidOperationException("HaloVPN service operation failed.", innerException)
{
    public string DiagnosticCode { get; } = diagnosticCode;
}

public sealed class ProcessNetworkCommandExecutor(ILogger<ProcessNetworkCommandExecutor> logger) : INetworkCommandExecutor
{
    private const int MaximumDiagnosticCharacters = 4096;

    static ProcessNetworkCommandExecutor()
    {
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
    }

    public async Task ExecuteAsync(
        NetworkCommand command,
        NetworkCommandContext context,
        CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo(command.FileName)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
        };
        if (OperatingSystem.IsWindows())
        {
            var oemEncoding = Encoding.GetEncoding(System.Globalization.CultureInfo.CurrentCulture.TextInfo.OEMCodePage);
            startInfo.StandardOutputEncoding = oemEncoding;
            startInfo.StandardErrorEncoding = oemEncoding;
        }
        foreach (var argument in command.Arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Network command could not be started.");
        var outputTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var errorTask = process.StandardError.ReadToEndAsync(cancellationToken);
        try
        {
            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException)
            {
            }

            throw;
        }

        var safeOutput = SanitizeDiagnostic(await outputTask.ConfigureAwait(false));
        var safeError = SanitizeDiagnostic(await errorTask.ConfigureAwait(false));
        if (process.ExitCode != 0)
        {
            logger.LogError(
                "Network command failed phase={Phase} mutationIndex={MutationIndex} mutationType={MutationType} file={File} arguments={Arguments} exit={ExitCode} stdout={Output} stderr={Error}",
                context.Phase,
                context.MutationIndex,
                context.MutationKind,
                command.FileName,
                string.Join(" ", command.Arguments),
                process.ExitCode,
                safeOutput,
                safeError);
            throw new NetworkCommandFailedException(command, context, process.ExitCode, safeOutput, safeError);
        }
    }

    private static string SanitizeDiagnostic(string value)
    {
        var normalized = new string(value
            .Where(character => character is '\r' or '\n' or '\t' || !char.IsControl(character))
            .Take(MaximumDiagnosticCharacters)
            .ToArray());
        return normalized.Trim();
    }
}

public sealed class VpnServiceCoordinator(
    IOptions<WindowsVpnServiceOptions> options,
    ProcessNetworkCommandExecutor networkExecutor,
    ILogger<VpnServiceCoordinator> logger)
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private CancellationTokenSource? _runCancellation;
    private Task? _runTask;
    private PersistentGuardRuntime? _guard;
    private WindowsGuardDescriptor? _recoveredDescriptor;
    private bool _invalidJournal;
    private ServiceStatusResponse _status = new("Disconnected", null, null);

    public ServiceStatusResponse Status => Volatile.Read(ref _status);

    public async Task RecoverOwnedNetworkStateAsync(CancellationToken cancellationToken)
    {
        var journal = new WindowsGuardJournal(options.Value.NetworkJournalPath);
        try
        {
            _recoveredDescriptor = await journal.LoadAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (InvalidDataException)
        {
            _invalidJournal = true;
            Volatile.Write(ref _status, new ServiceStatusResponse("FaultedProtected", null, "InvalidGuardJournal"));
            logger.LogError("Persistent network guard journal was rejected; no network commands were executed");
            return;
        }

        if (_recoveredDescriptor is not null)
        {
            Volatile.Write(ref _status, new ServiceStatusResponse("GuardedRecovery", _recoveredDescriptor.AssignedClientIpv4, null));
            logger.LogWarning("Persistent network guard from a previous service run remains active");
        }
    }

    public async Task<string> GetPublicKeyAsync(CancellationToken cancellationToken)
    {
        using var keys = await new DeviceKeyStore(options.Value.DeviceKeyPath).LoadOrCreateAsync(cancellationToken).ConfigureAwait(false);
        return Convert.ToBase64String(keys.PublicKey);
    }

    public async Task ConnectAsync(
        VpnProfileResponse profile,
        IReadOnlyList<string> bootstrapIpv4Addresses,
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_runTask is { IsCompleted: false })
            {
                throw new InvalidOperationException("A VPN session is already active.");
            }

            if (string.Equals(Status.State, "FaultedProtected", StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Explicit disconnect is required before reconnecting from a faulted protected state.");
            }

            Volatile.Write(ref _status, new ServiceStatusResponse("ConnectingProtected", profile.AssignedClientIpv4, null));
            var cancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            try
            {
                var guard = await EnsureGuardAsync(profile, bootstrapIpv4Addresses, cancellation.Token).ConfigureAwait(false);
                _guard = guard;
                TunnelRuntime? runtime = null;
                try
                {
                    runtime = await EstablishTransportAsync(profile, guard, cancellation.Token).ConfigureAwait(false);
                }
                catch (Exception exception) when (exception is IOException or InvalidOperationException or TimeoutException or SocketException or NotSupportedException)
                {
                    logger.LogWarning("Initial tunnel transport failed; protected reconnect scheduled code={Code}", exception.GetType().Name);
                }

                _runCancellation = cancellation;
                _runTask = RunAsync(runtime, profile, guard, cancellation);
                Volatile.Write(ref _status, runtime is null
                    ? new ServiceStatusResponse("ReconnectingProtected", profile.AssignedClientIpv4, "InitialHandshakeFailed")
                    : new ServiceStatusResponse("Connected", profile.AssignedClientIpv4, null));
            }
            catch
            {
                cancellation.Dispose();
                throw;
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task DisconnectAsync(CancellationToken cancellationToken)
    {
        Task? runTask;
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            _runCancellation?.Cancel();
            runTask = _runTask;
        }
        finally
        {
            _gate.Release();
        }

        if (runTask is not null)
        {
            try
            {
                await runTask.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
            }
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var cleanupSucceeded = !_invalidJournal;
            if (_guard is not null)
            {
                await _guard.DisposeAsync().ConfigureAwait(false);
                cleanupSucceeded = _guard.CleanupSucceeded;
                _guard = null;
            }
            else if (_recoveredDescriptor is not null)
            {
                try
                {
                    await new NetworkPlanTransaction(networkExecutor)
                        .RollbackAsync(
                            WindowsNetworkPlanBuilder.BuildRecoveryRollback(
                                _recoveredDescriptor,
                                IsInterfaceAvailable(_recoveredDescriptor.TunnelInterfaceIndex)),
                            cancellationToken)
                        .ConfigureAwait(false);
                    new WindowsGuardJournal(options.Value.NetworkJournalPath).Delete();
                    _recoveredDescriptor = null;
                }
                catch (Exception exception) when (exception is IOException or InvalidOperationException)
                {
                    cleanupSucceeded = false;
                    logger.LogWarning("Recovered guard cleanup was incomplete code={Code}", exception.GetType().Name);
                }
            }

            Volatile.Write(ref _status, cleanupSucceeded
                ? new ServiceStatusResponse("Disconnected", null, null)
                : new ServiceStatusResponse("FaultedProtected", null, "CleanupIncomplete"));
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task StopTransportPreservingGuardAsync(CancellationToken cancellationToken)
    {
        Task? runTask;
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            _runCancellation?.Cancel();
            runTask = _runTask;
        }
        finally
        {
            _gate.Release();
        }

        if (runTask is not null)
        {
            await runTask.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task<PersistentGuardRuntime> EnsureGuardAsync(
        VpnProfileResponse profile,
        IReadOnlyList<string> bootstrapIpv4Addresses,
        CancellationToken cancellationToken)
    {
        if (profile.Mtu is < 576 or > 1200 || profile.ProtocolVersion != 0)
        {
            throw new ArgumentException("VPN profile is incompatible with this service.", nameof(profile));
        }

        var configured = options.Value;
        IPAddress nodeAddress;
        if (_recoveredDescriptor is not null)
        {
            nodeAddress = IPAddress.Parse(_recoveredDescriptor.NodeIpv4);
        }
        else
        {
            var addresses = await Dns.GetHostAddressesAsync(profile.PublicHost, cancellationToken).ConfigureAwait(false);
            nodeAddress = addresses.FirstOrDefault(value => value.AddressFamily == AddressFamily.InterNetwork)
                ?? throw new InvalidOperationException("VPN node has no IPv4 address.");
        }

        WintunDevice? wintun = null;
        try
        {
            wintun = WintunDevice.Open(configured.WintunDllPath, configured.AdapterName);
            await InterfaceAppearanceWaiter.WaitAsync(
                () => IsInterfaceAvailable(wintun.InterfaceIndex),
                TimeSpan.FromSeconds(3),
                TimeSpan.FromMilliseconds(100),
                TimeProvider.System,
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is IOException or InvalidOperationException or TimeoutException or System.ComponentModel.Win32Exception)
        {
            if (wintun is not null)
            {
                await wintun.DisposeAsync().ConfigureAwait(false);
            }

            throw new VpnServiceOperationException("WintunAdapterCreateFailed", exception);
        }

        try
        {
            if (_recoveredDescriptor is not null)
            {
                var recovered = _recoveredDescriptor;
                if (!Matches(recovered, profile, nodeAddress, wintun.InterfaceIndex))
                {
                    throw new InvalidOperationException("Recovered guard does not match the requested VPN profile.");
                }

                _recoveredDescriptor = null;
                return new PersistentGuardRuntime(
                    wintun,
                    recovered,
                    WindowsNetworkPlanBuilder.Build(recovered),
                    networkExecutor,
                    new WindowsGuardJournal(configured.NetworkJournalPath),
                    logger);
            }

            var path = NetworkPathResolver.Resolve(nodeAddress);
            var descriptor = new WindowsGuardDescriptor(
                WindowsGuardDescriptor.CurrentVersion,
                configured.AdapterName,
                profile.AssignedClientIpv4,
                profile.TunnelGateway,
                profile.TunnelPrefixLength,
                profile.Mtu,
                nodeAddress.ToString(),
                profile.UdpPort,
                bootstrapIpv4Addresses,
                path.Gateway.ToString(),
                path.InterfaceIndex,
                wintun.InterfaceIndex,
                profile.DnsServers.Distinct(StringComparer.Ordinal).ToArray());
            descriptor.Validate();
            var plan = WindowsNetworkPlanBuilder.Build(descriptor);
            var journal = new WindowsGuardJournal(configured.NetworkJournalPath);
            await new NetworkPlanTransaction(networkExecutor).ApplyAsync(plan, cancellationToken).ConfigureAwait(false);
            var guard = new PersistentGuardRuntime(wintun, descriptor, plan, networkExecutor, journal, logger);
            try
            {
                await journal.SaveAsync(descriptor, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidDataException)
            {
                _guard = guard;
                Volatile.Write(ref _status, new ServiceStatusResponse("FaultedProtected", profile.AssignedClientIpv4, "JournalWriteFailed"));
                logger.LogError("Persistent guard is active but journal write failed code={Code}", exception.GetType().Name);
                throw new VpnServiceOperationException("JournalWriteFailed", exception);
            }

            return guard;
        }
        catch (NetworkPlanApplyException exception)
        {
            logger.LogError(
                "Persistent guard apply failed mutationIndex={MutationIndex} mutationType={MutationType} diagnosticCode={DiagnosticCode} rollbackSucceeded={RollbackSucceeded}",
                exception.MutationIndex,
                exception.MutationKind,
                exception.DiagnosticCode,
                exception.RollbackSucceeded);
            await wintun.DisposeAsync().ConfigureAwait(false);
            throw;
        }
        catch (VpnServiceOperationException)
        {
            throw;
        }
        catch
        {
            await wintun.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private async Task<TunnelRuntime> EstablishTransportAsync(
        VpnProfileResponse profile,
        PersistentGuardRuntime guard,
        CancellationToken cancellationToken)
    {
        var configured = options.Value;
        var carrier = new UdpCarrier(new IPEndPoint(IPAddress.Any, 0));
        NativeProtocolSession? session = null;
        try
        {
            using var keys = await new DeviceKeyStore(configured.DeviceKeyPath).LoadOrCreateAsync(cancellationToken).ConfigureAwait(false);
            var nodeKey = Convert.FromBase64String(profile.NodeNoisePublicKey);
            try
            {
                session = NativeProtocolSession.CreateClient(keys.PrivateKey, nodeKey);
            }
            finally
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(nodeKey);
            }

            var initiation = new ArrayBufferWriter<byte>(512);
            var written = session.WriteHandshake(initiation);
            if (!written.Success)
            {
                throw new InvalidOperationException($"Noise handshake creation failed: {written.ErrorCode}.");
            }

            async ValueTask<ReadOnlyMemory<byte>> ReceiveAsync(CancellationToken token)
            {
                while (true)
                {
                    var received = await carrier.ReceiveOneAsync(token).ConfigureAwait(false);
                    if (guard.Endpoint.Equals(received.RemoteEndPoint))
                    {
                        return received.Payload;
                    }
                }
            }

            var retransmitter = new HandshakeRetransmitter(new HandshakeRetransmissionOptions
            {
                Attempts = configured.HandshakeAttempts,
                InitialDelay = configured.HandshakeInitialDelay,
                MaximumDelay = configured.HandshakeMaximumDelay,
                TotalTimeout = configured.HandshakeTimeout,
            }, TimeProvider.System);
            var response = await retransmitter.ExchangeAsync(
                initiation.WrittenMemory,
                (payload, token) => carrier.SendAsync(payload, guard.Endpoint, token),
                ReceiveAsync,
                payload => HaloEnvelope.TryParse(payload.Span, out var envelope, out _) &&
                    envelope.Header.MessageType == ProtocolMessageType.HandshakeResponse &&
                    envelope.Header.ConnectionId == session.ConnectionId && envelope.Header.PacketNumber == 0,
                cancellationToken).ConfigureAwait(false);
            var sink = new ArrayBufferWriter<byte>();
            var result = session.ReadHandshake(response.Span, sink);
            if (!result.Success)
            {
                throw new InvalidOperationException($"Noise handshake was rejected: {result.ErrorCode}.");
            }

            logger.LogInformation("Tunnel established to node {Node} connection {ConnectionId}", profile.NodeName, session.ConnectionId);
            return new TunnelRuntime(
                carrier,
                guard.Wintun,
                session,
                guard.Endpoint,
                profile.Mtu,
                IPAddress.Parse(profile.AssignedClientIpv4),
                configured.KeepAliveInterval,
                configured.LivenessTimeout,
                TimeProvider.System,
                logger);
        }
        catch
        {
            session?.Dispose();
            await carrier.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private async Task RunAsync(
        TunnelRuntime? initialRuntime,
        VpnProfileResponse profile,
        PersistentGuardRuntime guard,
        CancellationTokenSource cancellation)
    {
        TunnelRuntime? runtime = initialRuntime;
        try
        {
            var reconnectDelay = TimeSpan.FromSeconds(1);
            while (!cancellation.IsCancellationRequested)
            {
                if (runtime is not null)
                {
                    var activeRuntime = runtime;
                    try
                    {
                        await activeRuntime.RunAsync(cancellation.Token).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
                    {
                        break;
                    }
                    catch (Exception exception)
                    {
                        logger.LogWarning("Tunnel transport failed; protected reconnect scheduled code={Code}", exception.GetType().Name);
                    }

                    runtime = null;
                    await activeRuntime.DisposeAsync().ConfigureAwait(false);
                }

                Volatile.Write(ref _status, new ServiceStatusResponse("ReconnectingProtected", profile.AssignedClientIpv4, "TransportLost"));
                using var drainCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellation.Token);
                var drainTask = guard.DrainAsync(drainCancellation.Token);
                try
                {
                    while (!cancellation.IsCancellationRequested && runtime is null)
                    {
                        await Task.Delay(reconnectDelay, cancellation.Token).ConfigureAwait(false);
                        try
                        {
                            runtime = await EstablishTransportAsync(profile, guard, cancellation.Token).ConfigureAwait(false);
                            reconnectDelay = TimeSpan.FromSeconds(1);
                            Volatile.Write(ref _status, new ServiceStatusResponse("Connected", profile.AssignedClientIpv4, null));
                        }
                        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
                        {
                            break;
                        }
                        catch (Exception exception) when (exception is IOException or InvalidOperationException or TimeoutException or SocketException)
                        {
                            logger.LogWarning("Reconnect attempt failed code={Code}", exception.GetType().Name);
                            reconnectDelay = TimeSpan.FromSeconds(Math.Min(reconnectDelay.TotalSeconds * 2, 30));
                        }
                    }
                }
                finally
                {
                    drainCancellation.Cancel();
                    try
                    {
                        await drainTask.ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (drainCancellation.IsCancellationRequested)
                    {
                    }
                }
            }
        }
        finally
        {
            if (runtime is not null)
            {
                await runtime.DisposeAsync().ConfigureAwait(false);
            }

            cancellation.Dispose();
            if (_guard is not null)
            {
                Volatile.Write(ref _status, new ServiceStatusResponse("FaultedProtected", profile.AssignedClientIpv4, "TransportStopped"));
            }
            await _gate.WaitAsync().ConfigureAwait(false);
            try
            {
                _runTask = null;
                _runCancellation = null;
            }
            finally
            {
                _gate.Release();
            }
        }
    }

    private static bool Matches(
        WindowsGuardDescriptor descriptor,
        VpnProfileResponse profile,
        IPAddress nodeAddress,
        int tunnelInterfaceIndex)
    {
        return string.Equals(descriptor.AssignedClientIpv4, profile.AssignedClientIpv4, StringComparison.Ordinal) &&
            string.Equals(descriptor.TunnelGateway, profile.TunnelGateway, StringComparison.Ordinal) &&
            descriptor.TunnelPrefixLength == profile.TunnelPrefixLength && descriptor.Mtu == profile.Mtu &&
            string.Equals(descriptor.NodeIpv4, nodeAddress.ToString(), StringComparison.Ordinal) &&
            descriptor.NodeUdpPort == profile.UdpPort &&
            descriptor.TunnelInterfaceIndex == tunnelInterfaceIndex;
    }

    private static bool IsInterfaceAvailable(int interfaceIndex)
    {
        foreach (var networkInterface in NetworkInterface.GetAllNetworkInterfaces())
        {
            try
            {
                if (networkInterface.GetIPProperties().GetIPv4Properties()?.Index == interfaceIndex)
                {
                    return true;
                }
            }
            catch (NetworkInformationException)
            {
                // Some Windows adapters expose no configured IPv4 protocol.
            }
        }

        return false;
    }
}

internal sealed record NetworkPath(IPAddress Gateway, int InterfaceIndex);

internal static class NetworkPathResolver
{
    internal static NetworkPath Resolve(IPAddress destination)
    {
        ArgumentNullException.ThrowIfNull(destination);
        using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        probe.Connect(new IPEndPoint(destination, 9));
        var selectedAddress = ((IPEndPoint?)probe.LocalEndPoint)?.Address
            ?? throw new InvalidOperationException("The operating system did not select a path to the VPN node.");
        var candidates = NetworkInterface.GetAllNetworkInterfaces()
            .Where(value => value.OperationalStatus == OperationalStatus.Up && value.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .Select(value => value.GetIPProperties())
            .Where(properties => properties.UnicastAddresses.Any(value => value.Address.Equals(selectedAddress)))
            .Select(properties => new
            {
                IPv4 = properties.GetIPv4Properties(),
                Gateway = properties.GatewayAddresses.Select(value => value.Address).FirstOrDefault(value => value.AddressFamily == AddressFamily.InterNetwork),
            })
            .Where(value => value.IPv4 is not null && value.Gateway is not null)
            .FirstOrDefault() ?? throw new InvalidOperationException("No active IPv4 default gateway was found.");
        return new NetworkPath(candidates.Gateway!, candidates.IPv4!.Index);
    }
}

internal sealed class PersistentGuardRuntime(
    WintunDevice wintun,
    WindowsGuardDescriptor descriptor,
    WindowsNetworkPlan networkPlan,
    INetworkCommandExecutor networkExecutor,
    WindowsGuardJournal journal,
    ILogger logger) : IAsyncDisposable
{
    internal WintunDevice Wintun => wintun;
    internal IPEndPoint Endpoint { get; } = new(IPAddress.Parse(descriptor.NodeIpv4), descriptor.NodeUdpPort);
    internal bool CleanupSucceeded { get; private set; } = true;

    internal async Task DrainAsync(CancellationToken cancellationToken)
    {
        var buffer = new byte[descriptor.Mtu];
        while (!cancellationToken.IsCancellationRequested)
        {
            _ = await wintun.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
        }
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            await new NetworkPlanTransaction(networkExecutor).RollbackAsync(networkPlan, CancellationToken.None).ConfigureAwait(false);
            journal.Delete();
        }
        catch (Exception exception) when (exception is IOException or InvalidOperationException)
        {
            CleanupSucceeded = false;
            logger.LogWarning("Persistent network guard cleanup was incomplete code={Code}", exception.GetType().Name);
        }

        await wintun.DisposeAsync().ConfigureAwait(false);
    }
}

internal sealed class TunnelRuntime(
    UdpCarrier carrier,
    WintunDevice wintun,
    NativeProtocolSession session,
    IPEndPoint endpoint,
    int mtu,
    IPAddress assignedSource,
    TimeSpan keepAliveInterval,
    TimeSpan livenessTimeout,
    TimeProvider timeProvider,
    ILogger logger) : IAsyncDisposable
{
    private readonly TunnelLivenessTracker _liveness = new(timeProvider, keepAliveInterval, livenessTimeout);
    private readonly byte[] _assignedSource = assignedSource.GetAddressBytes();
    private int _assignedSourceObserved;
    private int _unexpectedSourceObserved;

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var adapterPump = PumpAdapterAsync(linked.Token);
        var udpPump = PumpUdpAsync(linked.Token);
        var reliabilityPump = RunReliabilityAsync(linked.Token);
        var first = await Task.WhenAny(adapterPump, udpPump, reliabilityPump).ConfigureAwait(false);
        try
        {
            await first.ConfigureAwait(false);
        }
        catch
        {
            linked.Cancel();
            try
            {
                await Task.WhenAll(adapterPump, udpPump, reliabilityPump).ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is OperationCanceledException or IOException or InvalidOperationException or SocketException)
            {
            }

            throw;
        }

        linked.Cancel();
        try
        {
            await Task.WhenAll(adapterPump, udpPump, reliabilityPump).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (linked.IsCancellationRequested)
        {
        }

        cancellationToken.ThrowIfCancellationRequested();
        throw new IOException("A tunnel packet pump stopped unexpectedly.");
    }

    public async ValueTask DisposeAsync()
    {
        session.Dispose();
        await carrier.DisposeAsync().ConfigureAwait(false);
    }

    private async Task PumpAdapterAsync(CancellationToken cancellationToken)
    {
        var packet = new byte[mtu];
        while (!cancellationToken.IsCancellationRequested)
        {
            var length = await wintun.ReadAsync(packet, cancellationToken).ConfigureAwait(false);
            if (!IsValidIpv4(packet.AsSpan(0, length), mtu))
            {
                continue;
            }

            if (!packet.AsSpan(12, 4).SequenceEqual(_assignedSource))
            {
                if (Interlocked.Exchange(ref _unexpectedSourceObserved, 1) == 0)
                {
                    logger.LogWarning("Wintun packet rejected code=UnexpectedSource");
                }

                continue;
            }

            if (Interlocked.Exchange(ref _assignedSourceObserved, 1) == 0)
            {
                logger.LogInformation("Wintun packet accepted code=AssignedSource");
            }

            var encrypted = new ArrayBufferWriter<byte>(length + 64);
            var result = session.Encrypt(packet.AsSpan(0, length), encrypted);
            if (!result.Success)
            {
                throw new InvalidOperationException($"Packet encryption failed: {result.ErrorCode}.");
            }

            await carrier.SendAsync(encrypted.WrittenMemory, endpoint, cancellationToken).ConfigureAwait(false);
            _liveness.MarkOutbound();
        }
    }

    private async Task PumpUdpAsync(CancellationToken cancellationToken)
    {
        await foreach (var datagram in carrier.ReceiveAsync(cancellationToken).ConfigureAwait(false))
        {
            if (!endpoint.Equals(datagram.RemoteEndPoint))
            {
                continue;
            }

            if (!HaloEnvelope.TryParse(datagram.Payload.Span, out var envelope, out _))
            {
                continue;
            }

            var decrypted = new ArrayBufferWriter<byte>(mtu);
            var result = session.Decrypt(datagram.Payload.Span, decrypted);
            if (!result.Success)
            {
                continue;
            }

            _liveness.MarkInbound();
            if (envelope.Header.MessageType != ProtocolMessageType.Data || !IsValidIpv4(decrypted.WrittenSpan, mtu))
            {
                continue;
            }

            await wintun.WriteAsync(decrypted.WrittenMemory, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task RunReliabilityAsync(CancellationToken cancellationToken)
    {
        var tick = TimeSpan.FromMilliseconds(Math.Clamp(keepAliveInterval.TotalMilliseconds / 4, 250, 1000));
        using var timer = new PeriodicTimer(tick, timeProvider);
        while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
        {
            if (_liveness.HasTimedOut())
            {
                throw new TimeoutException("Authenticated tunnel liveness timed out.");
            }

            if (!_liveness.ShouldSendKeepAlive())
            {
                continue;
            }

            var keepAlive = new ArrayBufferWriter<byte>(128);
            var result = session.WriteKeepAlive(keepAlive);
            if (!result.Success)
            {
                throw new InvalidOperationException($"Keepalive encryption failed: {result.ErrorCode}.");
            }

            await carrier.SendAsync(keepAlive.WrittenMemory, endpoint, cancellationToken).ConfigureAwait(false);
            _liveness.MarkOutbound();
        }
    }

    private static bool IsValidIpv4(ReadOnlySpan<byte> packet, int mtu)
    {
        if (packet.Length is < 20 || packet.Length > mtu || (packet[0] >> 4) != 4)
        {
            return false;
        }

        var headerLength = (packet[0] & 0x0f) * 4;
        var totalLength = System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(packet[2..]);
        return headerLength >= 20 && headerLength <= packet.Length && totalLength == packet.Length;
    }
}

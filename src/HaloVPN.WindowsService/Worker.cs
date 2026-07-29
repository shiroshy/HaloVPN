using System.IO.Pipes;
using System.Net.NetworkInformation;
using System.Security.AccessControl;
using System.Security.Principal;
using HaloVPN.Contracts;
using HaloVPN.Platform.Windows;
using Microsoft.Extensions.Options;

namespace HaloVPN.WindowsService;

public sealed class Worker(
    VpnServiceCoordinator coordinator,
    IOptions<WindowsVpnServiceOptions> options,
    ILogger<Worker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("HaloVPN Windows Service only runs on Windows.");
        }

        var configured = options.Value;
        var allowedSid = new SecurityIdentifier(configured.AllowedUserSid);
        await coordinator.RecoverOwnedNetworkStateAsync(stoppingToken).ConfigureAwait(false);
        while (!stoppingToken.IsCancellationRequested)
        {
            await using var pipe = CreatePipe(configured.PipeName, allowedSid);
            try
            {
                await pipe.WaitForConnectionAsync(stoppingToken).ConfigureAwait(false);
                var request = await IpcProtocol.ReadAsync(pipe, stoppingToken).ConfigureAwait(false);
                var response = await HandleAsync(request, stoppingToken).ConfigureAwait(false);
                await IpcProtocol.WriteResponseAsync(pipe, response, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception) when (exception is IOException or InvalidDataException or UnauthorizedAccessException)
            {
                logger.LogWarning("IPC request rejected: {Code}", exception.GetType().Name);
            }
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await coordinator.StopTransportPreservingGuardAsync(cancellationToken).ConfigureAwait(false);
        await base.StopAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task<IpcResponse> HandleAsync(IpcRequest request, CancellationToken cancellationToken)
    {
        try
        {
            return request.Type switch
            {
                IpcMessageType.GetPublicKey => new IpcResponse(IpcProtocol.Version, true, await coordinator.GetPublicKeyAsync(cancellationToken).ConfigureAwait(false), coordinator.Status, null),
                IpcMessageType.Connect => await ConnectAsync(request.Profile!, request.BootstrapIpv4Addresses ?? [], cancellationToken).ConfigureAwait(false),
                IpcMessageType.Disconnect => await DisconnectAsync(cancellationToken).ConfigureAwait(false),
                IpcMessageType.GetStatus => new IpcResponse(IpcProtocol.Version, true, null, coordinator.Status, null),
                _ => throw new InvalidDataException("Unsupported IPC request type."),
            };
        }
        catch (Exception exception) when (exception is InvalidOperationException or IOException or TimeoutException or ArgumentException or NetworkInformationException)
        {
            var diagnosticCode = exception switch
            {
                NetworkPlanApplyException networkPlan => networkPlan.DiagnosticCode,
                VpnServiceOperationException operation => operation.DiagnosticCode,
                _ => exception.GetType().Name,
            };
            logger.LogWarning("Service request failed diagnosticCode={DiagnosticCode}", diagnosticCode);
            return new IpcResponse(IpcProtocol.Version, false, null, coordinator.Status, diagnosticCode);
        }
    }

    private async Task<IpcResponse> ConnectAsync(
        VpnProfileResponse profile,
        IReadOnlyList<string> bootstrapIpv4Addresses,
        CancellationToken cancellationToken)
    {
        await coordinator.ConnectAsync(profile, bootstrapIpv4Addresses, cancellationToken).ConfigureAwait(false);
        return new IpcResponse(IpcProtocol.Version, true, null, coordinator.Status, null);
    }

    private async Task<IpcResponse> DisconnectAsync(CancellationToken cancellationToken)
    {
        await coordinator.DisconnectAsync(cancellationToken).ConfigureAwait(false);
        return new IpcResponse(IpcProtocol.Version, true, null, coordinator.Status, null);
    }

    private static NamedPipeServerStream CreatePipe(string name, SecurityIdentifier allowedSid)
    {
        var security = new PipeSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new PipeAccessRule(allowedSid, PipeAccessRights.ReadWrite, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        return NamedPipeServerStreamAcl.Create(
            name,
            PipeDirection.InOut,
            1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.WriteThrough,
            4096,
            4096,
            security,
            HandleInheritability.None,
            PipeAccessRights.ChangePermissions);
    }
}

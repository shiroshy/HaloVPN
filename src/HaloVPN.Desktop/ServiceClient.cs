using System.IO.Pipes;
using HaloVPN.Contracts;
using HaloVPN.Platform.Windows;

namespace HaloVPN.Desktop;

internal sealed class ServiceClient(string pipeName = "HaloVPN.Service.v1")
{
    internal async Task<IpcResponse> SendAsync(
        IpcMessageType type,
        VpnProfileResponse? profile,
        CancellationToken cancellationToken,
        IReadOnlyList<string>? bootstrapIpv4Addresses = null)
    {
        await using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await pipe.ConnectAsync(TimeSpan.FromSeconds(5), cancellationToken).ConfigureAwait(false);
        await IpcProtocol.WriteAsync(pipe, new IpcRequest(IpcProtocol.Version, type, profile, bootstrapIpv4Addresses), cancellationToken).ConfigureAwait(false);
        var response = await IpcProtocol.ReadResponseAsync(pipe, cancellationToken).ConfigureAwait(false);
        if (!response.Success)
        {
            throw new InvalidOperationException($"HaloVPN Service rejected the request ({response.ErrorCode ?? "unknown"}).");
        }

        return response;
    }
}

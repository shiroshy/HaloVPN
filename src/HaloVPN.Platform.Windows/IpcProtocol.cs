using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using HaloVPN.Contracts;

namespace HaloVPN.Platform.Windows;

public enum IpcMessageType
{
    GetPublicKey = 1,
    Connect = 2,
    Disconnect = 3,
    GetStatus = 4,
}

public sealed record IpcRequest(
    int Version,
    IpcMessageType Type,
    VpnProfileResponse? Profile,
    IReadOnlyList<string>? BootstrapIpv4Addresses = null);

public sealed record IpcResponse(int Version, bool Success, string? PublicKey, ServiceStatusResponse? Status, string? ErrorCode);

public static class IpcProtocol
{
    public const int Version = 1;
    public const int MaximumMessageSize = 64 * 1024;

    public static async Task WriteAsync(Stream stream, IpcRequest request, CancellationToken cancellationToken)
    {
        Validate(request);
        var payload = JsonSerializer.SerializeToUtf8Bytes(request);
        if (payload.Length > MaximumMessageSize)
        {
            throw new InvalidDataException("IPC message exceeds the maximum size.");
        }

        var header = new byte[sizeof(int)];
        BinaryPrimitives.WriteInt32BigEndian(header, payload.Length);
        await stream.WriteAsync(header, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    public static async Task<IpcRequest> ReadAsync(Stream stream, CancellationToken cancellationToken)
    {
        var header = new byte[sizeof(int)];
        await stream.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);
        var length = BinaryPrimitives.ReadInt32BigEndian(header);
        if (length is <= 0 or > MaximumMessageSize)
        {
            throw new InvalidDataException("IPC message length is invalid.");
        }

        var payload = new byte[length];
        await stream.ReadExactlyAsync(payload, cancellationToken).ConfigureAwait(false);
        var request = JsonSerializer.Deserialize<IpcRequest>(payload) ?? throw new InvalidDataException("IPC request is empty.");
        Validate(request);
        return request;
    }

    public static Task WriteResponseAsync(Stream stream, IpcResponse response, CancellationToken cancellationToken) =>
        WritePayloadAsync(stream, JsonSerializer.SerializeToUtf8Bytes(response), cancellationToken);

    public static async Task<IpcResponse> ReadResponseAsync(Stream stream, CancellationToken cancellationToken)
    {
        var payload = await ReadPayloadAsync(stream, cancellationToken).ConfigureAwait(false);
        var response = JsonSerializer.Deserialize<IpcResponse>(payload) ?? throw new InvalidDataException("IPC response is empty.");
        if (response.Version != Version)
        {
            throw new InvalidDataException("IPC response version is invalid.");
        }

        return response;
    }

    private static void Validate(IpcRequest request)
    {
        if (request.Version != Version || !Enum.IsDefined(request.Type) ||
            (request.Type == IpcMessageType.Connect) != (request.Profile is not null))
        {
            throw new InvalidDataException("IPC request version, type, or payload is invalid.");
        }

        var bootstrap = request.BootstrapIpv4Addresses ?? [];
        if (request.Type == IpcMessageType.Connect && bootstrap.Count == 0 ||
            request.Type != IpcMessageType.Connect && bootstrap.Count != 0 || bootstrap.Count > 16 ||
            bootstrap.Distinct(StringComparer.Ordinal).Count() != bootstrap.Count ||
            bootstrap.Any(value => !IPAddress.TryParse(value, out var address) ||
                address.AddressFamily != AddressFamily.InterNetwork || IPAddress.Any.Equals(address) ||
                IPAddress.Loopback.Equals(address) || address.GetAddressBytes()[0] >= 224))
        {
            throw new InvalidDataException("IPC bootstrap endpoints are invalid.");
        }
    }

    private static async Task WritePayloadAsync(Stream stream, byte[] payload, CancellationToken cancellationToken)
    {
        if (payload.Length > MaximumMessageSize)
        {
            throw new InvalidDataException("IPC message exceeds the maximum size.");
        }

        var header = new byte[sizeof(int)];
        BinaryPrimitives.WriteInt32BigEndian(header, payload.Length);
        await stream.WriteAsync(header, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task<byte[]> ReadPayloadAsync(Stream stream, CancellationToken cancellationToken)
    {
        var header = new byte[sizeof(int)];
        await stream.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);
        var length = BinaryPrimitives.ReadInt32BigEndian(header);
        if (length is <= 0 or > MaximumMessageSize)
        {
            throw new InvalidDataException("IPC message length is invalid.");
        }

        var payload = new byte[length];
        await stream.ReadExactlyAsync(payload, cancellationToken).ConfigureAwait(false);
        return payload;
    }
}

public static class NamedPipeAuthorization
{
    public static bool IsAllowed(string configuredUserSid, string clientSid, bool clientIsAdministrator) =>
        !string.IsNullOrWhiteSpace(configuredUserSid) &&
        (clientIsAdministrator || string.Equals(configuredUserSid, clientSid, StringComparison.OrdinalIgnoreCase));
}

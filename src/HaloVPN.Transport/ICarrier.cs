using System.Net;

namespace HaloVPN.Transport;

public readonly record struct ReceivedDatagram(
    ReadOnlyMemory<byte> Payload,
    EndPoint RemoteEndPoint,
    DateTimeOffset ReceivedAt);

public interface ICarrier : IAsyncDisposable
{
    string Id { get; }

    int MaximumDatagramSize { get; }

    ValueTask SendAsync(
        ReadOnlyMemory<byte> datagram,
        EndPoint remoteEndPoint,
        CancellationToken cancellationToken);

    IAsyncEnumerable<ReceivedDatagram> ReceiveAsync(
        CancellationToken cancellationToken);
}

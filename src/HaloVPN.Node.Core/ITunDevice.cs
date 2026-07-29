namespace HaloVPN.Node.Core;

public interface ITunDevice : IAsyncDisposable
{
    string Name { get; }
    int Mtu { get; }
    ValueTask<int> ReadAsync(Memory<byte> destination, CancellationToken cancellationToken);
    ValueTask WriteAsync(ReadOnlyMemory<byte> packet, CancellationToken cancellationToken);
}

using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;

namespace HaloVPN.Transport;

public sealed class UdpCarrier : ICarrier
{
    public const int DefaultMaximumDatagramSize = 1400;
    private readonly Socket _socket;
    private readonly int _maximumDatagramSize;
    private int _disposed;

    public UdpCarrier(IPEndPoint localEndPoint, int maximumDatagramSize = DefaultMaximumDatagramSize)
    {
        ArgumentNullException.ThrowIfNull(localEndPoint);
        if (maximumDatagramSize is < 512 or > 65_507)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumDatagramSize));
        }

        _maximumDatagramSize = maximumDatagramSize;
        _socket = new Socket(localEndPoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp)
        {
            ReceiveBufferSize = 64 * 1024,
            SendBufferSize = 64 * 1024,
        };
        try
        {
            _socket.Bind(localEndPoint);
        }
        catch
        {
            _socket.Dispose();
            throw;
        }
    }

    public string Id => "udp";

    public int MaximumDatagramSize => _maximumDatagramSize;

    public IPEndPoint LocalEndPoint => (IPEndPoint)_socket.LocalEndPoint!;

    public async ValueTask SendAsync(
        ReadOnlyMemory<byte> datagram,
        EndPoint remoteEndPoint,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        ArgumentNullException.ThrowIfNull(remoteEndPoint);
        if (datagram.IsEmpty || datagram.Length > _maximumDatagramSize)
        {
            throw new ArgumentOutOfRangeException(nameof(datagram));
        }

        var sent = await _socket.SendToAsync(
            datagram,
            SocketFlags.None,
            remoteEndPoint,
            cancellationToken).ConfigureAwait(false);
        if (sent != datagram.Length)
        {
            throw new IOException("The UDP datagram was not sent atomically.");
        }
    }

    public async ValueTask<ReceivedDatagram> ReceiveOneAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        var receiveBuffer = new byte[_maximumDatagramSize + 1];
        EndPoint remoteTemplate = _socket.AddressFamily == AddressFamily.InterNetwork
            ? new IPEndPoint(IPAddress.Any, 0)
            : new IPEndPoint(IPAddress.IPv6Any, 0);

        while (true)
        {
            var received = await _socket.ReceiveFromAsync(
                receiveBuffer,
                SocketFlags.None,
                remoteTemplate,
                cancellationToken).ConfigureAwait(false);
            if (received.ReceivedBytes == 0 || received.ReceivedBytes > _maximumDatagramSize)
            {
                continue;
            }

            var datagram = GC.AllocateUninitializedArray<byte>(received.ReceivedBytes);
            receiveBuffer.AsSpan(0, received.ReceivedBytes).CopyTo(datagram);
            return new ReceivedDatagram(datagram, received.RemoteEndPoint, DateTimeOffset.UtcNow);
        }
    }

    public async IAsyncEnumerable<ReceivedDatagram> ReceiveAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        var receiveBuffer = new byte[_maximumDatagramSize + 1];
        EndPoint remoteTemplate = _socket.AddressFamily == AddressFamily.InterNetwork
            ? new IPEndPoint(IPAddress.Any, 0)
            : new IPEndPoint(IPAddress.IPv6Any, 0);

        while (!cancellationToken.IsCancellationRequested)
        {
            SocketReceiveFromResult received;
            try
            {
                received = await _socket.ReceiveFromAsync(
                    receiveBuffer,
                    SocketFlags.None,
                    remoteTemplate,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (ObjectDisposedException) when (Volatile.Read(ref _disposed) != 0)
            {
                yield break;
            }

            if (received.ReceivedBytes == 0 || received.ReceivedBytes > _maximumDatagramSize)
            {
                continue;
            }

            var datagram = GC.AllocateUninitializedArray<byte>(received.ReceivedBytes);
            receiveBuffer.AsSpan(0, received.ReceivedBytes).CopyTo(datagram);
            yield return new ReceivedDatagram(datagram, received.RemoteEndPoint, DateTimeOffset.UtcNow);
        }

        cancellationToken.ThrowIfCancellationRequested();
    }

    public ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _socket.Dispose();
        }

        return ValueTask.CompletedTask;
    }
}

public sealed record UdpSessionOptions
{
    public TimeSpan HandshakeTimeout { get; init; } = TimeSpan.FromSeconds(10);

    public TimeSpan IdleTimeout { get; init; } = TimeSpan.FromSeconds(180);

    public int MaximumPendingSessions { get; init; } = 1;

    public int MaximumHandshakeAttemptsPerWindow { get; init; } = 8;

    public TimeSpan HandshakeRateWindow { get; init; } = TimeSpan.FromSeconds(10);
}

public sealed class PendingHandshakeLimiter
{
    private readonly object _sync = new();
    private readonly UdpSessionOptions _options;
    private readonly Queue<DateTimeOffset> _attempts = new();
    private int _pending;

    public PendingHandshakeLimiter(UdpSessionOptions? options = null)
    {
        _options = options ?? new UdpSessionOptions();
        if (_options.MaximumPendingSessions <= 0 || _options.MaximumHandshakeAttemptsPerWindow <= 0 ||
            _options.HandshakeTimeout <= TimeSpan.Zero || _options.IdleTimeout <= TimeSpan.Zero ||
            _options.HandshakeRateWindow <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(options));
        }
    }

    public bool TryAcquire(DateTimeOffset now, out IDisposable? lease)
    {
        lock (_sync)
        {
            while (_attempts.TryPeek(out var oldest) && now - oldest >= _options.HandshakeRateWindow)
            {
                _attempts.Dequeue();
            }

            if (_pending >= _options.MaximumPendingSessions ||
                _attempts.Count >= _options.MaximumHandshakeAttemptsPerWindow)
            {
                lease = null;
                return false;
            }

            _pending++;
            _attempts.Enqueue(now);
            lease = new Lease(this);
            return true;
        }
    }

    private void Release()
    {
        lock (_sync)
        {
            if (_pending > 0)
            {
                _pending--;
            }
        }
    }

    private sealed class Lease(PendingHandshakeLimiter owner) : IDisposable
    {
        private PendingHandshakeLimiter? _owner = owner;

        public void Dispose() => Interlocked.Exchange(ref _owner, null)?.Release();
    }
}

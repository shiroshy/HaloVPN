using System.Net;
using HaloVPN.Transport;

namespace HaloVPN.Protocol.Tests;

public sealed class UdpCarrierTests
{
    [Fact]
    public async Task ReceiveCancellationAndHandshakeTimeoutAreObserved()
    {
        await using var carrier = new UdpCarrier(new IPEndPoint(IPAddress.Loopback, 0));
        using var timeout = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        await using var receiver = carrier.ReceiveAsync(timeout.Token).GetAsyncEnumerator();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await receiver.MoveNextAsync().AsTask());
    }

    [Fact]
    public async Task LoopbackSendAndReceiveUsesBoundedDatagrams()
    {
        await using var sender = new UdpCarrier(new IPEndPoint(IPAddress.Loopback, 0));
        await using var receiverCarrier = new UdpCarrier(new IPEndPoint(IPAddress.Loopback, 0));
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        await using var receiver = receiverCarrier.ReceiveAsync(timeout.Token).GetAsyncEnumerator();

        await sender.SendAsync(new byte[] { 1, 2, 3 }, receiverCarrier.LocalEndPoint, timeout.Token);
        Assert.True(await receiver.MoveNextAsync());
        Assert.Equal(new byte[] { 1, 2, 3 }, receiver.Current.Payload.ToArray());
    }

    [Fact]
    public async Task OneShotHandshakeReceiveCanTransitionToStreamingReceive()
    {
        await using var sender = new UdpCarrier(new IPEndPoint(IPAddress.Loopback, 0));
        await using var receiverCarrier = new UdpCarrier(new IPEndPoint(IPAddress.Loopback, 0));
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));

        var oneShot = receiverCarrier.ReceiveOneAsync(timeout.Token);
        await sender.SendAsync(new byte[] { 1 }, receiverCarrier.LocalEndPoint, timeout.Token);
        Assert.Equal(new byte[] { 1 }, (await oneShot).Payload.ToArray());

        await using var receiver = receiverCarrier.ReceiveAsync(timeout.Token).GetAsyncEnumerator();
        await sender.SendAsync(new byte[] { 2 }, receiverCarrier.LocalEndPoint, timeout.Token);
        Assert.True(await receiver.MoveNextAsync());
        Assert.Equal(new byte[] { 2 }, receiver.Current.Payload.ToArray());
    }

    [Fact]
    public void PendingHandshakeLimiterBoundsStateAndAttempts()
    {
        var now = DateTimeOffset.UtcNow;
        var limiter = new PendingHandshakeLimiter(new UdpSessionOptions
        {
            MaximumPendingSessions = 1,
            MaximumHandshakeAttemptsPerWindow = 2,
            HandshakeRateWindow = TimeSpan.FromSeconds(10),
        });

        Assert.True(limiter.TryAcquire(now, out var first));
        Assert.False(limiter.TryAcquire(now, out _));
        first!.Dispose();
        Assert.True(limiter.TryAcquire(now, out var second));
        second!.Dispose();
        Assert.False(limiter.TryAcquire(now, out _));
        Assert.True(limiter.TryAcquire(now.AddSeconds(11), out var afterWindow));
        afterWindow!.Dispose();
    }
}

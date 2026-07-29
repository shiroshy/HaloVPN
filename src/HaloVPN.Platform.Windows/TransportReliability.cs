namespace HaloVPN.Platform.Windows;

public sealed record HandshakeRetransmissionOptions
{
    public int Attempts { get; init; } = 4;
    public TimeSpan InitialDelay { get; init; } = TimeSpan.FromMilliseconds(500);
    public TimeSpan MaximumDelay { get; init; } = TimeSpan.FromSeconds(2);
    public TimeSpan TotalTimeout { get; init; } = TimeSpan.FromSeconds(10);
}

public sealed class HandshakeRetransmitter(
    HandshakeRetransmissionOptions options,
    TimeProvider timeProvider)
{
    public async Task<ReadOnlyMemory<byte>> ExchangeAsync(
        ReadOnlyMemory<byte> exactInitiation,
        Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> sendAsync,
        Func<CancellationToken, ValueTask<ReadOnlyMemory<byte>>> receiveAsync,
        Func<ReadOnlyMemory<byte>, bool> acceptResponse,
        CancellationToken cancellationToken)
    {
        Validate();
        ArgumentNullException.ThrowIfNull(sendAsync);
        ArgumentNullException.ThrowIfNull(receiveAsync);
        ArgumentNullException.ThrowIfNull(acceptResponse);
        if (exactInitiation.IsEmpty)
        {
            throw new ArgumentException("Handshake initiation cannot be empty.", nameof(exactInitiation));
        }

        var initiation = exactInitiation.ToArray();
        using var receiveCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var receiveTask = ReceiveAcceptedAsync(receiveAsync, acceptResponse, receiveCancellation.Token);
        var timeoutTask = Task.Delay(options.TotalTimeout, timeProvider, cancellationToken);
        var delay = options.InitialDelay;
        try
        {
            for (var attempt = 0; attempt < options.Attempts; attempt++)
            {
                await sendAsync(initiation, cancellationToken).ConfigureAwait(false);
                if (receiveTask.IsCompleted)
                {
                    return await receiveTask.ConfigureAwait(false);
                }

                if (attempt == options.Attempts - 1)
                {
                    break;
                }

                var retryDelay = Task.Delay(delay, timeProvider, cancellationToken);
                var completed = await Task.WhenAny(receiveTask, retryDelay, timeoutTask).ConfigureAwait(false);
                if (completed == receiveTask)
                {
                    return await receiveTask.ConfigureAwait(false);
                }

                if (completed == timeoutTask)
                {
                    await timeoutTask.ConfigureAwait(false);
                    throw new TimeoutException("Noise handshake timed out.");
                }

                delay = TimeSpan.FromTicks(Math.Min(delay.Ticks * 2, options.MaximumDelay.Ticks));
            }

            if (await Task.WhenAny(receiveTask, timeoutTask).ConfigureAwait(false) == receiveTask)
            {
                return await receiveTask.ConfigureAwait(false);
            }

            await timeoutTask.ConfigureAwait(false);
            throw new TimeoutException("Noise handshake timed out.");
        }
        finally
        {
            receiveCancellation.Cancel();
            try
            {
                await receiveTask.ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (receiveCancellation.IsCancellationRequested)
            {
            }
        }
    }

    private static async Task<ReadOnlyMemory<byte>> ReceiveAcceptedAsync(
        Func<CancellationToken, ValueTask<ReadOnlyMemory<byte>>> receiveAsync,
        Func<ReadOnlyMemory<byte>, bool> acceptResponse,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            var response = await receiveAsync(cancellationToken).ConfigureAwait(false);
            if (acceptResponse(response))
            {
                return response;
            }
        }
    }

    private void Validate()
    {
        if (options.Attempts is < 1 or > 16 || options.InitialDelay <= TimeSpan.Zero ||
            options.MaximumDelay < options.InitialDelay || options.MaximumDelay > TimeSpan.FromSeconds(10) ||
            options.TotalTimeout <= options.InitialDelay || options.TotalTimeout > TimeSpan.FromMinutes(1))
        {
            throw new InvalidOperationException("Handshake retransmission options are outside supported bounds.");
        }
    }
}

public sealed class TunnelLivenessTracker
{
    private readonly TimeProvider _timeProvider;
    private readonly TimeSpan _keepAliveInterval;
    private readonly TimeSpan _livenessTimeout;
    private long _lastInboundTicks;
    private long _lastOutboundTicks;

    public TunnelLivenessTracker(TimeProvider timeProvider, TimeSpan keepAliveInterval, TimeSpan livenessTimeout)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        if (keepAliveInterval <= TimeSpan.Zero || livenessTimeout <= keepAliveInterval ||
            livenessTimeout > TimeSpan.FromMinutes(10))
        {
            throw new ArgumentOutOfRangeException(nameof(keepAliveInterval));
        }

        _timeProvider = timeProvider;
        _keepAliveInterval = keepAliveInterval;
        _livenessTimeout = livenessTimeout;
        var now = timeProvider.GetUtcNow().UtcTicks;
        _lastInboundTicks = now;
        _lastOutboundTicks = now;
    }

    public void MarkInbound() => Interlocked.Exchange(ref _lastInboundTicks, _timeProvider.GetUtcNow().UtcTicks);

    public void MarkOutbound() => Interlocked.Exchange(ref _lastOutboundTicks, _timeProvider.GetUtcNow().UtcTicks);

    public bool ShouldSendKeepAlive() =>
        _timeProvider.GetUtcNow() - new DateTimeOffset(Interlocked.Read(ref _lastOutboundTicks), TimeSpan.Zero) >= _keepAliveInterval;

    public bool HasTimedOut() =>
        _timeProvider.GetUtcNow() - new DateTimeOffset(Interlocked.Read(ref _lastInboundTicks), TimeSpan.Zero) >= _livenessTimeout;
}

using System.Net;

namespace HaloVPN.Node.Core;

public sealed class NodeHandshakeRateLimiter(NodeSessionOptions options)
{
    private readonly object _sync = new();
    private readonly Dictionary<IPAddress, SourceState> _sources = [];
    private int _pending;

    public bool TryAcquire(IPAddress sourceAddress, DateTimeOffset now, out IDisposable? lease)
    {
        ArgumentNullException.ThrowIfNull(sourceAddress);
        lock (_sync)
        {
            Prune(now);
            if (!_sources.TryGetValue(sourceAddress, out var state))
            {
                if (_sources.Count >= 256)
                {
                    lease = null;
                    return false;
                }

                state = new SourceState();
                _sources.Add(sourceAddress, state);
            }

            while (state.Attempts.TryPeek(out var oldest) && now - oldest >= options.AttemptWindow)
            {
                state.Attempts.Dequeue();
            }

            if (_pending >= options.MaximumPendingHandshakes || state.Pending >= options.MaximumPendingPerSource ||
                state.Attempts.Count >= options.MaximumAttemptsPerSourceWindow)
            {
                lease = null;
                return false;
            }

            _pending++;
            state.Pending++;
            state.Attempts.Enqueue(now);
            lease = new Lease(this, sourceAddress);
            return true;
        }
    }

    private void Prune(DateTimeOffset now)
    {
        foreach (var pair in _sources.ToArray())
        {
            while (pair.Value.Attempts.TryPeek(out var oldest) && now - oldest >= options.AttemptWindow)
            {
                pair.Value.Attempts.Dequeue();
            }

            if (pair.Value.Pending == 0 && pair.Value.Attempts.Count == 0)
            {
                _sources.Remove(pair.Key);
            }
        }
    }

    private void Release(IPAddress sourceAddress)
    {
        lock (_sync)
        {
            if (_sources.TryGetValue(sourceAddress, out var state) && state.Pending > 0)
            {
                state.Pending--;
                _pending--;
            }
        }
    }

    private sealed class SourceState
    {
        internal Queue<DateTimeOffset> Attempts { get; } = [];
        internal int Pending { get; set; }
    }

    private sealed class Lease(NodeHandshakeRateLimiter owner, IPAddress sourceAddress) : IDisposable
    {
        private NodeHandshakeRateLimiter? _owner = owner;
        public void Dispose() => Interlocked.Exchange(ref _owner, null)?.Release(sourceAddress);
    }
}

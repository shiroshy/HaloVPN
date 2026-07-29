using HaloVPN.Infrastructure;

namespace HaloVPN.Node.Core;

public sealed record AuthorizationCacheOptions
{
    public int MaximumDevices { get; init; } = 64;
    public TimeSpan RefreshInterval { get; init; } = TimeSpan.FromSeconds(15);
    public TimeSpan MaximumStaleAge { get; init; } = TimeSpan.FromMinutes(2);
}

public sealed record AuthorizationSnapshot(
    IReadOnlyList<AuthorizedDevice> Devices,
    DateTimeOffset LoadedAt,
    bool CanAuthorizeNewSessions);

public sealed class AuthorizationCache(
    INodeAuthorizationRepository repository,
    AuthorizationCacheOptions options,
    TimeProvider timeProvider)
{
    private readonly SemaphoreSlim _refreshLock = new(1, 1);
    private AuthorizationSnapshot? _current;

    public async Task<AuthorizationSnapshot> GetAsync(CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow();
        var snapshot = Volatile.Read(ref _current);
        if (snapshot is not null && now - snapshot.LoadedAt < options.RefreshInterval)
        {
            return snapshot;
        }

        await _refreshLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            now = timeProvider.GetUtcNow();
            snapshot = _current;
            if (snapshot is not null && now - snapshot.LoadedAt < options.RefreshInterval)
            {
                return snapshot;
            }

            try
            {
                var devices = await repository.GetAuthorizedDevicesAsync(options.MaximumDevices, cancellationToken).ConfigureAwait(false);
                var fresh = new AuthorizationSnapshot(devices, now, true);
                Volatile.Write(ref _current, fresh);
                return fresh;
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                if (snapshot is not null && now - snapshot.LoadedAt <= options.MaximumStaleAge)
                {
                    var stale = snapshot with { CanAuthorizeNewSessions = false };
                    Volatile.Write(ref _current, stale);
                    return stale;
                }

                return new AuthorizationSnapshot([], now, false);
            }
        }
        finally
        {
            _refreshLock.Release();
        }
    }
}

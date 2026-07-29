using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using HaloVPN.Protocol.Abstractions;
using HaloVPN.Protocol.Interop;

namespace HaloVPN.Node.Core;

public sealed record HandshakeResponseCacheOptions
{
    public int MaximumEntries { get; init; } = 128;
    public int MaximumEntriesPerSource { get; init; } = 8;
    public TimeSpan TimeToLive { get; init; } = TimeSpan.FromSeconds(15);
}

public sealed class HandshakeResponseCache
{
    private readonly object _sync = new();
    private readonly HandshakeResponseCacheOptions _options;
    private readonly Dictionary<CacheKey, CacheEntry> _entries = [];

    public HandshakeResponseCache(HandshakeResponseCacheOptions options)
    {
        _options = options;
        if (options.MaximumEntries is < 1 or > 4096 || options.MaximumEntriesPerSource is < 1 or > 64 ||
            options.MaximumEntriesPerSource > options.MaximumEntries || options.TimeToLive <= TimeSpan.Zero || options.TimeToLive > TimeSpan.FromMinutes(1))
        {
            throw new ArgumentOutOfRangeException(nameof(options));
        }
    }

    public int Count
    {
        get { lock (_sync) { return _entries.Count; } }
    }

    public bool TryGet(IPEndPoint endpoint, ReadOnlySpan<byte> initiation, DateTimeOffset now, out ReadOnlyMemory<byte> response)
    {
        response = default;
        if (!TryCreateKey(endpoint, initiation, out var key))
        {
            return false;
        }

        lock (_sync)
        {
            Prune(now);
            if (!_entries.TryGetValue(key, out var entry))
            {
                return false;
            }

            response = entry.Response;
            return true;
        }
    }

    public bool TryStore(
        IPEndPoint endpoint,
        ReadOnlySpan<byte> initiation,
        ReadOnlySpan<byte> response,
        DateTimeOffset now)
    {
        if (response.IsEmpty || response.Length > initiation.Length || !TryCreateKey(endpoint, initiation, out var key))
        {
            return false;
        }

        lock (_sync)
        {
            Prune(now);
            if (_entries.ContainsKey(key))
            {
                return true;
            }

            var sourceCount = _entries.Count(value => value.Key.Address.Equals(endpoint.Address));
            if (_entries.Count >= _options.MaximumEntries || sourceCount >= _options.MaximumEntriesPerSource)
            {
                return false;
            }

            _entries.Add(key, new CacheEntry(response.ToArray(), now.Add(_options.TimeToLive)));
            return true;
        }
    }

    private void Prune(DateTimeOffset now)
    {
        foreach (var pair in _entries.Where(value => value.Value.ExpiresAt <= now).ToArray())
        {
            _entries.Remove(pair.Key);
        }
    }

    private static bool TryCreateKey(IPEndPoint endpoint, ReadOnlySpan<byte> initiation, out CacheKey key)
    {
        key = default;
        if (!HaloEnvelope.TryParse(initiation, out var envelope, out _) ||
            envelope.Header.MessageType != ProtocolMessageType.HandshakeInit || envelope.Header.ConnectionId == 0)
        {
            return false;
        }

        Span<byte> digest = stackalloc byte[32];
        SHA256.HashData(initiation, digest);
        key = new CacheKey(
            endpoint.Address,
            endpoint.Port,
            envelope.Header.ConnectionId,
            BinaryPrimitives.ReadUInt64BigEndian(digest),
            BinaryPrimitives.ReadUInt64BigEndian(digest[8..]),
            BinaryPrimitives.ReadUInt64BigEndian(digest[16..]),
            BinaryPrimitives.ReadUInt64BigEndian(digest[24..]));
        CryptographicOperations.ZeroMemory(digest);
        return true;
    }

    private readonly record struct CacheKey(
        IPAddress Address,
        int Port,
        ulong ConnectionId,
        ulong Digest0,
        ulong Digest1,
        ulong Digest2,
        ulong Digest3);

    private sealed record CacheEntry(byte[] Response, DateTimeOffset ExpiresAt);
}

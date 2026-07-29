namespace HaloVPN.Shared;

public static class HaloProtocolConstants
{
    public const ushort Magic = 0x4856;
    public const byte WireVersion = 0x00;
    public const int CommonHeaderSize = 24;
    public const int AuthenticationTagSize = 16;
    public const int MaximumUnauthenticatedDatagramSize = 512;
    public const int MaximumAuthenticatedDatagramSize = 1400;
    public const int MaximumStageZeroPlaintextSize = 1200;
    public const int ReplayWindowSize = 2048;
    public const ulong SessionMessageLimit = 1UL << 32;

    public static readonly TimeSpan HandshakeLifetime = TimeSpan.FromSeconds(10);
    public static readonly TimeSpan DefaultIdleTimeout = TimeSpan.FromSeconds(180);
    public static readonly TimeSpan DefaultKeepAliveInterval = TimeSpan.FromSeconds(25);
}

public sealed record ProtocolLimits
{
    public TimeSpan MaximumSessionAge { get; init; } = TimeSpan.FromHours(2);

    public ulong MaximumPacketsPerDirection { get; init; } = 1UL << 32;

    public ulong MaximumBytesPerDirection { get; init; } = 64UL * 1024 * 1024 * 1024;
}

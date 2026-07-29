using HaloVPN.Protocol.Abstractions;

namespace HaloVPN.Protocol.Interop;

public sealed class NativeProtocolException : InvalidOperationException
{
    internal NativeProtocolException(NativeErrorCode nativeErrorCode)
        : base($"Native protocol operation failed with safe error code {nativeErrorCode}.")
    {
        NativeErrorCode = (uint)nativeErrorCode;
        ProtocolErrorCode = NativeError.Map(nativeErrorCode);
    }

    public uint NativeErrorCode { get; }

    public ProtocolErrorCode ProtocolErrorCode { get; }
}

internal static class NativeError
{
    internal static ProtocolErrorCode Map(NativeErrorCode code) => code switch
    {
        NativeErrorCode.Success => ProtocolErrorCode.None,
        NativeErrorCode.InvalidArgument => ProtocolErrorCode.InvalidArgument,
        NativeErrorCode.InvalidState or NativeErrorCode.InvalidHandle => ProtocolErrorCode.InvalidState,
        NativeErrorCode.InvalidPacket => ProtocolErrorCode.InvalidPacket,
        NativeErrorCode.UnsupportedVersion => ProtocolErrorCode.UnsupportedVersion,
        NativeErrorCode.AuthenticationFailed => ProtocolErrorCode.AuthenticationFailed,
        NativeErrorCode.ReplayDetected => ProtocolErrorCode.ReplayDetected,
        NativeErrorCode.CapacityExceeded or NativeErrorCode.BufferTooSmall => ProtocolErrorCode.CapacityExceeded,
        NativeErrorCode.KeyLimitReached => ProtocolErrorCode.KeyLimitReached,
        _ => ProtocolErrorCode.InternalError,
    };

    internal static void ThrowIfFailed(NativeErrorCode code)
    {
        if (code != NativeErrorCode.Success)
        {
            throw new NativeProtocolException(code);
        }
    }
}

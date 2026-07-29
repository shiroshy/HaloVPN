using System.Buffers;

namespace HaloVPN.Protocol.Abstractions;

public enum ProtocolRole
{
    Client = 0,
    Server = 1,
}

public enum ProtocolSessionState
{
    Created = 0,
    Handshaking = 1,
    Established = 2,
    Closing = 3,
    Closed = 4,
    Faulted = 5,
}

public enum ProtocolMessageType : byte
{
    HandshakeInit = 0x01,
    HandshakeResponse = 0x02,
    Data = 0x10,
    KeepAlive = 0x11,
    Close = 0x12,
}

public enum ProtocolErrorCode
{
    None = 0,
    InvalidArgument,
    InvalidState,
    InvalidPacket,
    UnsupportedVersion,
    AuthenticationFailed,
    ReplayDetected,
    CapacityExceeded,
    KeyLimitReached,
    InternalError,
}

public readonly record struct ProtocolOperationResult(
    bool Success,
    ProtocolErrorCode ErrorCode,
    int BytesWritten)
{
    public static ProtocolOperationResult Ok(int bytesWritten) =>
        new(true, ProtocolErrorCode.None, bytesWritten);

    public static ProtocolOperationResult Fail(ProtocolErrorCode errorCode) =>
        new(false, errorCode, 0);
}

public interface IProtocolSession : IDisposable
{
    ProtocolRole Role { get; }

    ProtocolSessionState State { get; }

    ulong ConnectionId { get; }

    ProtocolOperationResult WriteHandshake(IBufferWriter<byte> destination);

    ProtocolOperationResult ReadHandshake(
        ReadOnlySpan<byte> packet,
        IBufferWriter<byte> responseDestination);

    ProtocolOperationResult Encrypt(
        ReadOnlySpan<byte> plaintext,
        IBufferWriter<byte> destination);

    ProtocolOperationResult Decrypt(
        ReadOnlySpan<byte> packet,
        IBufferWriter<byte> plaintextDestination);

    ProtocolOperationResult WriteKeepAlive(IBufferWriter<byte> destination);

    ProtocolOperationResult WriteClose(
        ushort reason,
        uint detail,
        IBufferWriter<byte> destination);
}

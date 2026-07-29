using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using HaloVPN.Protocol.Abstractions;
using HaloVPN.Shared;

namespace HaloVPN.Protocol.Interop;

public sealed class NativeProtocolSession : IProtocolSession
{
    private const int NativeHandshakeCapacity = 512;
    private const int DataPayloadHeaderSize = 4;
    private readonly object _sync = new();
    private readonly SafeProtocolSessionHandle _handle;
    private ProtocolSessionState _state = ProtocolSessionState.Created;
    private ulong _nextPacketNumber;
    private bool _disposed;

    private NativeProtocolSession(ProtocolRole role, SafeProtocolSessionHandle handle, ulong connectionId)
    {
        Role = role;
        _handle = handle;
        ConnectionId = connectionId;
    }

    public ProtocolRole Role { get; }

    public ProtocolSessionState State
    {
        get
        {
            lock (_sync)
            {
                return _state;
            }
        }
    }

    public ulong ConnectionId { get; private set; }

    public static NativeProtocolSession CreateClient(
        ReadOnlySpan<byte> clientPrivateKey,
        ReadOnlySpan<byte> serverPublicKey,
        ulong connectionId = 0)
    {
        ValidateKey(clientPrivateKey, nameof(clientPrivateKey));
        ValidateKey(serverPublicKey, nameof(serverPublicKey));
        NativeProtocolLibrary.EnsureAvailable();
        connectionId = connectionId == 0 ? CreateConnectionId() : connectionId;

        NativeErrorCode error;
        ulong value;
        unsafe
        {
            fixed (byte* localPointer = clientPrivateKey)
            fixed (byte* remotePointer = serverPublicKey)
            {
                error = NativeMethods.CreateClient(
                    localPointer,
                    (nuint)clientPrivateKey.Length,
                    remotePointer,
                    (nuint)serverPublicKey.Length,
                    out value);
            }
        }

        NativeError.ThrowIfFailed(error);
        return new NativeProtocolSession(ProtocolRole.Client, new SafeProtocolSessionHandle(value), connectionId);
    }

    public static NativeProtocolSession CreateServer(
        ReadOnlySpan<byte> serverPrivateKey,
        ReadOnlySpan<byte> allowedClientPublicKey)
    {
        ValidateKey(serverPrivateKey, nameof(serverPrivateKey));
        ValidateKey(allowedClientPublicKey, nameof(allowedClientPublicKey));
        NativeProtocolLibrary.EnsureAvailable();

        NativeErrorCode error;
        ulong value;
        unsafe
        {
            fixed (byte* localPointer = serverPrivateKey)
            fixed (byte* remotePointer = allowedClientPublicKey)
            {
                error = NativeMethods.CreateServer(
                    localPointer,
                    (nuint)serverPrivateKey.Length,
                    remotePointer,
                    (nuint)allowedClientPublicKey.Length,
                    out value);
            }
        }

        NativeError.ThrowIfFailed(error);
        return new NativeProtocolSession(ProtocolRole.Server, new SafeProtocolSessionHandle(value), 0);
    }

    public ProtocolOperationResult WriteHandshake(IBufferWriter<byte> destination)
    {
        ArgumentNullException.ThrowIfNull(destination);
        lock (_sync)
        {
            ThrowIfDisposed();
            if (Role != ProtocolRole.Client || _state is not ProtocolSessionState.Created)
            {
                return ProtocolOperationResult.Fail(ProtocolErrorCode.InvalidState);
            }

            var result = WriteNativeHandshakeEnvelope(destination, ProtocolMessageType.HandshakeInit);
            if (result.Success)
            {
                _state = ProtocolSessionState.Handshaking;
            }

            return result;
        }
    }

    public ProtocolOperationResult ReadHandshake(
        ReadOnlySpan<byte> packet,
        IBufferWriter<byte> responseDestination)
    {
        ArgumentNullException.ThrowIfNull(responseDestination);
        lock (_sync)
        {
            ThrowIfDisposed();
            if (!HaloEnvelope.TryParse(packet, out var envelope, out var parseError))
            {
                return ProtocolOperationResult.Fail(parseError);
            }

            var expectedType = Role == ProtocolRole.Client
                ? ProtocolMessageType.HandshakeResponse
                : ProtocolMessageType.HandshakeInit;
            var expectedState = Role == ProtocolRole.Client
                ? ProtocolSessionState.Handshaking
                : ProtocolSessionState.Created;
            if (_state != expectedState || envelope.Header.MessageType != expectedType ||
                envelope.Header.PacketNumber != 0 || envelope.Header.ConnectionId == 0 ||
                (Role == ProtocolRole.Client && envelope.Header.ConnectionId != ConnectionId))
            {
                return ProtocolOperationResult.Fail(ProtocolErrorCode.InvalidState);
            }

            var nativeError = NativeReadHandshake(envelope.Payload);
            if (nativeError != NativeErrorCode.Success)
            {
                if (nativeError == NativeErrorCode.AuthenticationFailed)
                {
                    _state = ProtocolSessionState.Faulted;
                }

                return ProtocolOperationResult.Fail(NativeError.Map(nativeError));
            }

            if (Role == ProtocolRole.Server)
            {
                ConnectionId = envelope.Header.ConnectionId;
                _state = ProtocolSessionState.Handshaking;
                var response = WriteNativeHandshakeEnvelope(responseDestination, ProtocolMessageType.HandshakeResponse);
                if (!response.Success)
                {
                    _state = ProtocolSessionState.Faulted;
                    return response;
                }

                _state = ProtocolSessionState.Established;
                return response;
            }

            _state = IsNativeEstablished() ? ProtocolSessionState.Established : ProtocolSessionState.Faulted;
            return _state == ProtocolSessionState.Established
                ? ProtocolOperationResult.Ok(0)
                : ProtocolOperationResult.Fail(ProtocolErrorCode.InvalidState);
        }
    }

    public ProtocolOperationResult Encrypt(ReadOnlySpan<byte> plaintext, IBufferWriter<byte> destination)
    {
        ArgumentNullException.ThrowIfNull(destination);
        if (plaintext.Length > HaloProtocolConstants.MaximumStageZeroPlaintextSize)
        {
            return ProtocolOperationResult.Fail(ProtocolErrorCode.InvalidArgument);
        }

        lock (_sync)
        {
            ThrowIfDisposed();
            return WriteTransportPacket(ProtocolMessageType.Data, plaintext, 0, 0, destination);
        }
    }

    public ProtocolOperationResult Decrypt(ReadOnlySpan<byte> packet, IBufferWriter<byte> plaintextDestination)
    {
        ArgumentNullException.ThrowIfNull(plaintextDestination);
        lock (_sync)
        {
            ThrowIfDisposed();
            if (_state != ProtocolSessionState.Established)
            {
                return ProtocolOperationResult.Fail(ProtocolErrorCode.InvalidState);
            }

            if (!HaloEnvelope.TryParse(packet, out var envelope, out var parseError))
            {
                return ProtocolOperationResult.Fail(parseError);
            }

            if (envelope.Header.ConnectionId != ConnectionId ||
                envelope.Header.MessageType is not (ProtocolMessageType.Data or ProtocolMessageType.KeepAlive or ProtocolMessageType.Close))
            {
                return ProtocolOperationResult.Fail(ProtocolErrorCode.InvalidPacket);
            }

            var maximumPlaintext = envelope.Payload.Length - HaloProtocolConstants.AuthenticationTagSize;
            if (maximumPlaintext < HaloEnvelope.HeaderSize)
            {
                return ProtocolOperationResult.Fail(ProtocolErrorCode.InvalidPacket);
            }

            var temporary = new byte[maximumPlaintext];
            try
            {
                var nativeError = NativeDecrypt(
                    envelope.Header.PacketNumber,
                    packet[..HaloEnvelope.HeaderSize],
                    envelope.Payload,
                    temporary,
                    out var written);
                if (nativeError != NativeErrorCode.Success)
                {
                    return ProtocolOperationResult.Fail(NativeError.Map(nativeError));
                }

                var protectedPayload = temporary.AsSpan(HaloEnvelope.HeaderSize, written - HaloEnvelope.HeaderSize);
                return ProcessProtectedPayload(envelope.Header.MessageType, protectedPayload, plaintextDestination);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(temporary);
            }
        }
    }

    public ProtocolOperationResult WriteKeepAlive(IBufferWriter<byte> destination)
    {
        ArgumentNullException.ThrowIfNull(destination);
        lock (_sync)
        {
            ThrowIfDisposed();
            return WriteTransportPacket(ProtocolMessageType.KeepAlive, [], 0, 0, destination);
        }
    }

    public ProtocolOperationResult WriteClose(ushort reason, uint detail, IBufferWriter<byte> destination)
    {
        ArgumentNullException.ThrowIfNull(destination);
        lock (_sync)
        {
            ThrowIfDisposed();
            var result = WriteTransportPacket(ProtocolMessageType.Close, [], reason, detail, destination);
            if (result.Success)
            {
                _state = ProtocolSessionState.Closing;
            }

            return result;
        }
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _state = ProtocolSessionState.Closed;
            _handle.Dispose();
        }

        GC.SuppressFinalize(this);
    }

    private ProtocolOperationResult WriteNativeHandshakeEnvelope(
        IBufferWriter<byte> destination,
        ProtocolMessageType messageType)
    {
        var nativeMessage = new byte[NativeHandshakeCapacity];
        try
        {
            var nativeError = NativeWriteHandshake(nativeMessage, out var nativeLength);
            if (nativeError != NativeErrorCode.Success)
            {
                return ProtocolOperationResult.Fail(NativeError.Map(nativeError));
            }

            var totalLength = HaloEnvelope.HeaderSize + nativeLength;
            var output = destination.GetSpan(totalLength)[..totalLength];
            HaloEnvelope.WriteHeader(output, new HaloEnvelopeHeader(
                messageType,
                0,
                ConnectionId,
                0,
                checked((ushort)nativeLength)));
            nativeMessage.AsSpan(0, nativeLength).CopyTo(output[HaloEnvelope.HeaderSize..]);
            destination.Advance(totalLength);
            return ProtocolOperationResult.Ok(totalLength);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nativeMessage);
        }
    }

    private ProtocolOperationResult WriteTransportPacket(
        ProtocolMessageType messageType,
        ReadOnlySpan<byte> applicationPayload,
        ushort closeReason,
        uint closeDetail,
        IBufferWriter<byte> destination)
    {
        if (_state != ProtocolSessionState.Established)
        {
            return ProtocolOperationResult.Fail(
                _nextPacketNumber >= HaloProtocolConstants.SessionMessageLimit
                    ? ProtocolErrorCode.KeyLimitReached
                    : ProtocolErrorCode.InvalidState);
        }

        if (_nextPacketNumber >= HaloProtocolConstants.SessionMessageLimit)
        {
            _state = ProtocolSessionState.Closing;
            return ProtocolOperationResult.Fail(ProtocolErrorCode.KeyLimitReached);
        }

        var protectedDataLength = messageType switch
        {
            ProtocolMessageType.Data => DataPayloadHeaderSize + applicationPayload.Length,
            ProtocolMessageType.KeepAlive => 0,
            ProtocolMessageType.Close => 8,
            _ => throw new InvalidOperationException("Unsupported transport message type."),
        };
        var nativePlaintextLength = HaloEnvelope.HeaderSize + protectedDataLength;
        var ciphertextLength = nativePlaintextLength + HaloProtocolConstants.AuthenticationTagSize;
        var totalLength = HaloEnvelope.HeaderSize + ciphertextLength;
        var output = destination.GetSpan(totalLength)[..totalLength];
        var header = new HaloEnvelopeHeader(
            messageType,
            0,
            ConnectionId,
            _nextPacketNumber,
            checked((ushort)ciphertextLength));
        HaloEnvelope.WriteHeader(output, header);

        var temporary = new byte[nativePlaintextLength];
        try
        {
            output[..HaloEnvelope.HeaderSize].CopyTo(temporary);
            var inner = temporary.AsSpan(HaloEnvelope.HeaderSize);
            if (messageType == ProtocolMessageType.Data)
            {
                inner[0] = 0;
                inner[1] = 0;
                BinaryPrimitives.WriteUInt16BigEndian(inner[2..], checked((ushort)applicationPayload.Length));
                applicationPayload.CopyTo(inner[DataPayloadHeaderSize..]);
            }
            else if (messageType == ProtocolMessageType.Close)
            {
                BinaryPrimitives.WriteUInt16BigEndian(inner, closeReason);
                BinaryPrimitives.WriteUInt16BigEndian(inner[2..], 0);
                BinaryPrimitives.WriteUInt32BigEndian(inner[4..], closeDetail);
            }

            var nativeError = NativeEncrypt(
                _nextPacketNumber,
                temporary,
                output[HaloEnvelope.HeaderSize..],
                out var written);
            if (nativeError != NativeErrorCode.Success)
            {
                return ProtocolOperationResult.Fail(NativeError.Map(nativeError));
            }

            if (written != ciphertextLength)
            {
                _state = ProtocolSessionState.Faulted;
                return ProtocolOperationResult.Fail(ProtocolErrorCode.InternalError);
            }

            _nextPacketNumber++;
            destination.Advance(totalLength);
            return ProtocolOperationResult.Ok(totalLength);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(temporary);
        }
    }

    private ProtocolOperationResult ProcessProtectedPayload(
        ProtocolMessageType messageType,
        ReadOnlySpan<byte> payload,
        IBufferWriter<byte> destination)
    {
        if (messageType == ProtocolMessageType.KeepAlive)
        {
            return payload.IsEmpty
                ? ProtocolOperationResult.Ok(0)
                : ProtocolOperationResult.Fail(ProtocolErrorCode.InvalidPacket);
        }

        if (messageType == ProtocolMessageType.Close)
        {
            if (payload.Length != 8 || BinaryPrimitives.ReadUInt16BigEndian(payload[2..]) != 0)
            {
                return ProtocolOperationResult.Fail(ProtocolErrorCode.InvalidPacket);
            }

            _state = ProtocolSessionState.Closed;
            return ProtocolOperationResult.Ok(0);
        }

        if (payload.Length < DataPayloadHeaderSize || payload[0] != 0 || payload[1] != 0)
        {
            return ProtocolOperationResult.Fail(ProtocolErrorCode.InvalidPacket);
        }

        var payloadLength = BinaryPrimitives.ReadUInt16BigEndian(payload[2..]);
        if (payloadLength > HaloProtocolConstants.MaximumStageZeroPlaintextSize ||
            DataPayloadHeaderSize + payloadLength != payload.Length)
        {
            return ProtocolOperationResult.Fail(ProtocolErrorCode.InvalidPacket);
        }

        var output = destination.GetSpan(payloadLength)[..payloadLength];
        payload[DataPayloadHeaderSize..].CopyTo(output);
        destination.Advance(payloadLength);
        return ProtocolOperationResult.Ok(payloadLength);
    }

    private unsafe NativeErrorCode NativeWriteHandshake(Span<byte> destination, out int written)
    {
        fixed (byte* outputPointer = destination)
        {
            var error = NativeMethods.WriteHandshake(
                _handle,
                outputPointer,
                (nuint)destination.Length,
                out var length);
            written = checked((int)length);
            return error;
        }
    }

    private unsafe NativeErrorCode NativeReadHandshake(ReadOnlySpan<byte> message)
    {
        fixed (byte* inputPointer = message)
        {
            return NativeMethods.ReadHandshake(_handle, inputPointer, (nuint)message.Length);
        }
    }

    private unsafe NativeErrorCode NativeEncrypt(
        ulong packetNumber,
        ReadOnlySpan<byte> plaintext,
        Span<byte> destination,
        out int written)
    {
        fixed (byte* plaintextPointer = plaintext)
        fixed (byte* outputPointer = destination)
        {
            var error = NativeMethods.Encrypt(
                _handle,
                packetNumber,
                plaintextPointer,
                (nuint)plaintext.Length,
                outputPointer,
                (nuint)destination.Length,
                out var length);
            written = checked((int)length);
            return error;
        }
    }

    private unsafe NativeErrorCode NativeDecrypt(
        ulong packetNumber,
        ReadOnlySpan<byte> expectedPrefix,
        ReadOnlySpan<byte> ciphertext,
        Span<byte> destination,
        out int written)
    {
        fixed (byte* prefixPointer = expectedPrefix)
        fixed (byte* ciphertextPointer = ciphertext)
        fixed (byte* outputPointer = destination)
        {
            var error = NativeMethods.Decrypt(
                _handle,
                packetNumber,
                prefixPointer,
                (nuint)expectedPrefix.Length,
                ciphertextPointer,
                (nuint)ciphertext.Length,
                outputPointer,
                (nuint)destination.Length,
                out var length);
            written = checked((int)length);
            return error;
        }
    }

    private bool IsNativeEstablished()
    {
        var error = NativeMethods.IsEstablished(_handle, out var established);
        return error == NativeErrorCode.Success && established == 1;
    }

    private static void ValidateKey(ReadOnlySpan<byte> key, string parameterName)
    {
        if (key.Length != NativeProtocolLibrary.KeySize)
        {
            throw new ArgumentException("X25519 keys must contain exactly 32 bytes.", parameterName);
        }
    }

    private static ulong CreateConnectionId()
    {
        Span<byte> bytes = stackalloc byte[sizeof(ulong)];
        ulong value;
        do
        {
            RandomNumberGenerator.Fill(bytes);
            value = BinaryPrimitives.ReadUInt64BigEndian(bytes);
        }
        while (value == 0);

        CryptographicOperations.ZeroMemory(bytes);
        return value;
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }
}

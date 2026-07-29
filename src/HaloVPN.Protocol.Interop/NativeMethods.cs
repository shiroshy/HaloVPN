using System.Runtime.InteropServices;

namespace HaloVPN.Protocol.Interop;

internal enum NativeErrorCode : uint
{
    Success = 0,
    InvalidArgument = 1,
    InvalidState = 2,
    InvalidPacket = 3,
    UnsupportedVersion = 4,
    AuthenticationFailed = 5,
    ReplayDetected = 6,
    CapacityExceeded = 7,
    KeyLimitReached = 8,
    BufferTooSmall = 9,
    InvalidHandle = 10,
    InternalError = 255,
}

internal static unsafe partial class NativeMethods
{
    [LibraryImport(NativeProtocolLibrary.BaseName, EntryPoint = "halo_abi_version")]
    internal static partial uint AbiVersion();

    [LibraryImport(NativeProtocolLibrary.BaseName, EntryPoint = "halo_session_create_client")]
    internal static partial NativeErrorCode CreateClient(
        byte* localPrivate,
        nuint localLength,
        byte* remotePublic,
        nuint remoteLength,
        out ulong handle);

    [LibraryImport(NativeProtocolLibrary.BaseName, EntryPoint = "halo_session_create_server")]
    internal static partial NativeErrorCode CreateServer(
        byte* localPrivate,
        nuint localLength,
        byte* allowedPublic,
        nuint allowedLength,
        out ulong handle);

    [LibraryImport(NativeProtocolLibrary.BaseName, EntryPoint = "halo_session_write_handshake")]
    internal static partial NativeErrorCode WriteHandshake(
        SafeProtocolSessionHandle handle,
        byte* output,
        nuint outputCapacity,
        out nuint outputLength);

    [LibraryImport(NativeProtocolLibrary.BaseName, EntryPoint = "halo_session_read_handshake")]
    internal static partial NativeErrorCode ReadHandshake(
        SafeProtocolSessionHandle handle,
        byte* input,
        nuint inputLength);

    [LibraryImport(NativeProtocolLibrary.BaseName, EntryPoint = "halo_session_encrypt")]
    internal static partial NativeErrorCode Encrypt(
        SafeProtocolSessionHandle handle,
        ulong packetNumber,
        byte* plaintext,
        nuint plaintextLength,
        byte* output,
        nuint outputCapacity,
        out nuint outputLength);

    [LibraryImport(NativeProtocolLibrary.BaseName, EntryPoint = "halo_session_decrypt")]
    internal static partial NativeErrorCode Decrypt(
        SafeProtocolSessionHandle handle,
        ulong packetNumber,
        byte* expectedPrefix,
        nuint expectedPrefixLength,
        byte* ciphertext,
        nuint ciphertextLength,
        byte* output,
        nuint outputCapacity,
        out nuint outputLength);

    [LibraryImport(NativeProtocolLibrary.BaseName, EntryPoint = "halo_session_is_established")]
    internal static partial NativeErrorCode IsEstablished(SafeProtocolSessionHandle handle, out byte established);

    [LibraryImport(NativeProtocolLibrary.BaseName, EntryPoint = "halo_session_destroy")]
    internal static partial NativeErrorCode Destroy(ulong handle);

    [LibraryImport(NativeProtocolLibrary.BaseName, EntryPoint = "halo_generate_keypair")]
    internal static partial NativeErrorCode GenerateKeyPair(
        byte* privateKey,
        nuint privateCapacity,
        byte* publicKey,
        nuint publicCapacity);
}

internal sealed class SafeProtocolSessionHandle : SafeHandle
{
    private SafeProtocolSessionHandle()
        : base(IntPtr.Zero, true)
    {
    }

    internal SafeProtocolSessionHandle(ulong value)
        : this()
    {
        SetHandle(new IntPtr(checked((long)value)));
    }

    public override bool IsInvalid => handle == IntPtr.Zero;

    protected override bool ReleaseHandle() =>
        NativeMethods.Destroy(checked((ulong)handle.ToInt64())) is NativeErrorCode.Success or NativeErrorCode.InvalidHandle;
}

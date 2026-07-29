using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace HaloVPN.Platform.Windows;

public sealed partial class WintunDevice : IAsyncDisposable
{
    private const int ErrorNoMoreItems = 259;
    private readonly IntPtr _library;
    private readonly NativeApi _api;
    private readonly IntPtr _adapter;
    private readonly IntPtr _session;
    private readonly EventWaitHandle _readEvent;
    private int _disposed;

    private WintunDevice(IntPtr library, NativeApi api, IntPtr adapter, IntPtr session, EventWaitHandle readEvent, int interfaceIndex)
    {
        _library = library;
        _api = api;
        _adapter = adapter;
        _session = session;
        _readEvent = readEvent;
        InterfaceIndex = interfaceIndex;
    }

    public int InterfaceIndex { get; }

    public static WintunDevice Open(string dllPath, string adapterName = "HaloVPN", uint ringCapacity = 0x400000)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Wintun requires Windows.");
        }

        var fullPath = Path.GetFullPath(dllPath);
        if (!string.Equals(Path.GetFileName(fullPath), "wintun.dll", StringComparison.OrdinalIgnoreCase) || !File.Exists(fullPath))
        {
            throw new FileNotFoundException("The official x64 wintun.dll must be placed at the configured path.", fullPath);
        }

        if (ringCapacity is < 0x20000 or > 0x4000000 || (ringCapacity & (ringCapacity - 1)) != 0)
        {
            throw new ArgumentOutOfRangeException(nameof(ringCapacity), "Wintun ring capacity must be a supported power of two.");
        }

        var library = NativeLibrary.Load(fullPath);
        IntPtr adapter = IntPtr.Zero;
        IntPtr session = IntPtr.Zero;
        try
        {
            var api = NativeApi.Load(library);
            adapter = api.OpenAdapter(adapterName);
            if (adapter == IntPtr.Zero)
            {
                adapter = api.CreateAdapter(adapterName, "HaloVPN", IntPtr.Zero);
            }

            if (adapter == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "Wintun adapter creation failed.");
            }

            session = api.StartSession(adapter, ringCapacity);
            if (session == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "Wintun session creation failed.");
            }

            var eventHandle = api.GetReadWaitEvent(session);
            if (eventHandle == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "Wintun read event is unavailable.");
            }

            api.GetAdapterLuid(adapter, out var luid);
            var convertResult = NativeMethods.ConvertInterfaceLuidToIndex(ref luid, out var interfaceIndex);
            if (convertResult != 0)
            {
                throw new Win32Exception((int)convertResult, "Wintun interface index lookup failed.");
            }

            var waitHandle = new EventWaitHandle(false, EventResetMode.AutoReset)
            {
                SafeWaitHandle = new SafeWaitHandle(eventHandle, ownsHandle: false),
            };
            return new WintunDevice(library, api, adapter, session, waitHandle, checked((int)interfaceIndex));
        }
        catch
        {
            if (session != IntPtr.Zero)
            {
                NativeApi.TryEndSession(library, session);
            }

            if (adapter != IntPtr.Zero)
            {
                NativeApi.TryCloseAdapter(library, adapter);
            }

            NativeLibrary.Free(library);
            throw;
        }
    }

    public async ValueTask<int> ReadAsync(Memory<byte> destination, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        while (true)
        {
            var packet = _api.ReceivePacket(_session, out var size);
            if (packet != IntPtr.Zero)
            {
                try
                {
                    if (size == 0 || size > destination.Length)
                    {
                        throw new InvalidDataException("Wintun packet exceeds the bounded destination buffer.");
                    }

                    unsafe
                    {
                        // SAFETY: Wintun owns a readable packet of `size` bytes until ReleaseReceivePacket.
                        new ReadOnlySpan<byte>(packet.ToPointer(), checked((int)size)).CopyTo(destination.Span);
                    }

                    return checked((int)size);
                }
                finally
                {
                    _api.ReleaseReceivePacket(_session, packet);
                }
            }

            var error = Marshal.GetLastPInvokeError();
            if (error != ErrorNoMoreItems)
            {
                throw new Win32Exception(error, "Wintun packet receive failed.");
            }

            await WaitOneAsync(_readEvent, cancellationToken).ConfigureAwait(false);
        }
    }

    public ValueTask WriteAsync(ReadOnlyMemory<byte> packet, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        cancellationToken.ThrowIfCancellationRequested();
        if (packet.IsEmpty || packet.Length > 1200)
        {
            throw new ArgumentOutOfRangeException(nameof(packet));
        }

        var destination = _api.AllocateSendPacket(_session, checked((uint)packet.Length));
        if (destination == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError(), "Wintun send allocation failed.");
        }

        unsafe
        {
            // SAFETY: Wintun returned writable storage of exactly packet.Length bytes for this session.
            packet.Span.CopyTo(new Span<byte>(destination.ToPointer(), packet.Length));
        }

        _api.SendPacket(_session, destination);
        return ValueTask.CompletedTask;
    }

    public ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _readEvent.Dispose();
            _api.EndSession(_session);
            _api.CloseAdapter(_adapter);
            NativeLibrary.Free(_library);
        }

        return ValueTask.CompletedTask;
    }

    private static Task WaitOneAsync(WaitHandle waitHandle, CancellationToken cancellationToken)
    {
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        RegisteredWaitHandle? registration = null;
        CancellationTokenRegistration cancellationRegistration = default;
        registration = ThreadPool.RegisterWaitForSingleObject(
            waitHandle,
            (_, _) => completion.TrySetResult(),
            null,
            Timeout.Infinite,
            executeOnlyOnce: true);
        if (cancellationToken.CanBeCanceled)
        {
            cancellationRegistration = cancellationToken.Register(() => completion.TrySetCanceled(cancellationToken));
        }

        return AwaitAndCleanupAsync(completion.Task, registration, cancellationRegistration);
    }

    private static async Task AwaitAndCleanupAsync(
        Task task,
        RegisteredWaitHandle registration,
        CancellationTokenRegistration cancellationRegistration)
    {
        try
        {
            await task.ConfigureAwait(false);
        }
        finally
        {
            registration.Unregister(null);
            cancellationRegistration.Dispose();
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NetLuid
    {
        internal ulong Value;
    }

    private sealed class NativeApi
    {
        internal required CreateAdapterDelegate CreateAdapter { get; init; }
        internal required OpenAdapterDelegate OpenAdapter { get; init; }
        internal required CloseAdapterDelegate CloseAdapter { get; init; }
        internal required GetAdapterLuidDelegate GetAdapterLuid { get; init; }
        internal required StartSessionDelegate StartSession { get; init; }
        internal required EndSessionDelegate EndSession { get; init; }
        internal required GetReadWaitEventDelegate GetReadWaitEvent { get; init; }
        internal required ReceivePacketDelegate ReceivePacket { get; init; }
        internal required ReleaseReceivePacketDelegate ReleaseReceivePacket { get; init; }
        internal required AllocateSendPacketDelegate AllocateSendPacket { get; init; }
        internal required SendPacketDelegate SendPacket { get; init; }

        internal static NativeApi Load(IntPtr library) => new()
        {
            CreateAdapter = Load<CreateAdapterDelegate>(library, "WintunCreateAdapter"),
            OpenAdapter = Load<OpenAdapterDelegate>(library, "WintunOpenAdapter"),
            CloseAdapter = Load<CloseAdapterDelegate>(library, "WintunCloseAdapter"),
            GetAdapterLuid = Load<GetAdapterLuidDelegate>(library, "WintunGetAdapterLUID"),
            StartSession = Load<StartSessionDelegate>(library, "WintunStartSession"),
            EndSession = Load<EndSessionDelegate>(library, "WintunEndSession"),
            GetReadWaitEvent = Load<GetReadWaitEventDelegate>(library, "WintunGetReadWaitEvent"),
            ReceivePacket = Load<ReceivePacketDelegate>(library, "WintunReceivePacket"),
            ReleaseReceivePacket = Load<ReleaseReceivePacketDelegate>(library, "WintunReleaseReceivePacket"),
            AllocateSendPacket = Load<AllocateSendPacketDelegate>(library, "WintunAllocateSendPacket"),
            SendPacket = Load<SendPacketDelegate>(library, "WintunSendPacket"),
        };

        internal static void TryEndSession(IntPtr library, IntPtr session)
        {
            if (NativeLibrary.TryGetExport(library, "WintunEndSession", out var address))
            {
                Marshal.GetDelegateForFunctionPointer<EndSessionDelegate>(address)(session);
            }
        }

        internal static void TryCloseAdapter(IntPtr library, IntPtr adapter)
        {
            if (NativeLibrary.TryGetExport(library, "WintunCloseAdapter", out var address))
            {
                Marshal.GetDelegateForFunctionPointer<CloseAdapterDelegate>(address)(adapter);
            }
        }

        private static T Load<T>(IntPtr library, string name) where T : Delegate =>
            Marshal.GetDelegateForFunctionPointer<T>(NativeLibrary.GetExport(library, name));
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode, SetLastError = true)]
    private delegate IntPtr CreateAdapterDelegate(string name, string tunnelType, IntPtr requestedGuid);
    [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode, SetLastError = true)]
    private delegate IntPtr OpenAdapterDelegate(string name);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void CloseAdapterDelegate(IntPtr adapter);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void GetAdapterLuidDelegate(IntPtr adapter, out NetLuid luid);
    [UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)]
    private delegate IntPtr StartSessionDelegate(IntPtr adapter, uint capacity);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void EndSessionDelegate(IntPtr session);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate IntPtr GetReadWaitEventDelegate(IntPtr session);
    [UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)]
    private delegate IntPtr ReceivePacketDelegate(IntPtr session, out uint packetSize);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void ReleaseReceivePacketDelegate(IntPtr session, IntPtr packet);
    [UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)]
    private delegate IntPtr AllocateSendPacketDelegate(IntPtr session, uint packetSize);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void SendPacketDelegate(IntPtr session, IntPtr packet);

    private static partial class NativeMethods
    {
        [LibraryImport("iphlpapi.dll")]
        internal static partial uint ConvertInterfaceLuidToIndex(ref NetLuid interfaceLuid, out uint interfaceIndex);
    }
}

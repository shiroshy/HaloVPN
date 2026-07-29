using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using HaloVPN.Node.Core;
using Microsoft.Win32.SafeHandles;

namespace HaloVPN.Platform.Linux;

public sealed partial class LinuxTunDevice : ITunDevice
{
    private const uint TunSetInterface = 0x400454CA;
    private const short InterfaceTun = 0x0001;
    private const short NoPacketInformation = 0x1000;
    private readonly FileStream _readStream;
    private readonly FileStream _writeStream;

    private LinuxTunDevice(string name, int mtu, FileStream readStream, FileStream writeStream)
    {
        Name = name;
        Mtu = mtu;
        _readStream = readStream;
        _writeStream = writeStream;
    }

    public string Name { get; }
    public int Mtu { get; }

    public static async Task<LinuxTunDevice> CreateAsync(
        string name,
        string gatewayCidr,
        int mtu,
        CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("Linux TUN is available only on Linux.");
        }

        ValidateName(name);
        if (mtu is < 576 or > 9000)
        {
            throw new ArgumentOutOfRangeException(nameof(mtu));
        }

        var handle = File.OpenHandle(
            "/dev/net/tun",
            FileMode.Open,
            FileAccess.ReadWrite,
            FileShare.ReadWrite,
            FileOptions.Asynchronous);
        try
        {
            ConfigureInterface(handle, name);
            await RunIpAsync(["address", "replace", gatewayCidr, "dev", name], cancellationToken).ConfigureAwait(false);
            await RunIpAsync(["link", "set", "dev", name, "mtu", mtu.ToString(System.Globalization.CultureInfo.InvariantCulture), "up"], cancellationToken).ConfigureAwait(false);
            var duplicatedDescriptor = NativeMethods.Dup(handle);
            if (duplicatedDescriptor < 0)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "TUN file descriptor duplication failed.");
            }

            var writeHandle = new SafeFileHandle(new IntPtr(duplicatedDescriptor), ownsHandle: true);
            try
            {
                var readStream = new FileStream(handle, FileAccess.ReadWrite, 4096, isAsync: true);
                // dup(2) preserves O_NONBLOCK but SafeFileHandle cannot carry the
                // managed async metadata of the original handle. Writes to TUN are
                // short and use a separate descriptor, so a synchronous FileStream
                // cannot serialize behind the pending asynchronous read.
                var writeStream = new FileStream(writeHandle, FileAccess.ReadWrite, 4096, isAsync: false);
                return new LinuxTunDevice(name, mtu, readStream, writeStream);
            }
            catch
            {
                writeHandle.Dispose();
                throw;
            }
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    public ValueTask<int> ReadAsync(Memory<byte> destination, CancellationToken cancellationToken)
    {
        if (destination.Length < Mtu)
        {
            throw new ArgumentException("TUN receive buffer is smaller than the configured MTU.", nameof(destination));
        }

        return _readStream.ReadAsync(destination[..Mtu], cancellationToken);
    }

    public async ValueTask WriteAsync(ReadOnlyMemory<byte> packet, CancellationToken cancellationToken)
    {
        if (packet.IsEmpty || packet.Length > Mtu)
        {
            throw new ArgumentOutOfRangeException(nameof(packet));
        }

        await _writeStream.WriteAsync(packet, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        await _writeStream.DisposeAsync().ConfigureAwait(false);
        await _readStream.DisposeAsync().ConfigureAwait(false);
    }

    private static unsafe void ConfigureInterface(SafeFileHandle handle, string name)
    {
        Span<byte> request = stackalloc byte[40];
        var encoded = Encoding.ASCII.GetBytes(name);
        encoded.CopyTo(request);
        BitConverter.TryWriteBytes(request[16..], (short)(InterfaceTun | NoPacketInformation));
        fixed (byte* requestPointer = request)
        {
            // SAFETY: request points to a writable Linux ifreq-sized buffer for the duration of ioctl.
            if (NativeMethods.Ioctl(handle, TunSetInterface, requestPointer) < 0)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "TUNSETIFF failed.");
            }
        }
    }

    private static async Task RunIpAsync(IReadOnlyList<string> arguments, CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "/usr/sbin/ip",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Failed to start ip command.");
        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        if (process.ExitCode != 0)
        {
            var error = await process.StandardError.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
            throw new InvalidOperationException($"ip command failed with exit code {process.ExitCode}: {error.Trim()}");
        }
    }

    private static void ValidateName(string name)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Length > 15 || name.Any(character => !(char.IsAsciiLetterOrDigit(character) || character is '_' or '-')))
        {
            throw new ArgumentException("TUN name must be 1-15 ASCII letters, digits, underscore, or dash.", nameof(name));
        }
    }

    private static partial class NativeMethods
    {
        [LibraryImport("libc", EntryPoint = "ioctl", SetLastError = true)]
        internal static unsafe partial int Ioctl(SafeFileHandle fileDescriptor, uint request, byte* argument);

        [LibraryImport("libc", EntryPoint = "dup", SetLastError = true)]
        internal static partial int Dup(SafeFileHandle fileDescriptor);
    }
}

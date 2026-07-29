using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace HaloVPN.Protocol.Interop;

public static class NativeProtocolLibrary
{
    public const string BaseName = "halo_protocol";
    public const int KeySize = 32;

    static NativeProtocolLibrary()
    {
        NativeLibrary.SetDllImportResolver(typeof(NativeProtocolLibrary).Assembly, Resolve);
    }

    public static bool IsAvailable()
    {
        try
        {
            return NativeMethods.AbiVersion() == 1;
        }
        catch (DllNotFoundException)
        {
            return false;
        }
        catch (BadImageFormatException)
        {
            return false;
        }
    }

    public static (byte[] PrivateKey, byte[] PublicKey) GenerateKeyPair()
    {
        EnsureAvailable();
        var privateKey = new byte[KeySize];
        var publicKey = new byte[KeySize];
        try
        {
            unsafe
            {
                fixed (byte* privatePointer = privateKey)
                fixed (byte* publicPointer = publicKey)
                {
                    NativeError.ThrowIfFailed(NativeMethods.GenerateKeyPair(
                        privatePointer,
                        KeySize,
                        publicPointer,
                        KeySize));
                }
            }

            return (privateKey, publicKey);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(privateKey);
            throw;
        }
    }

    internal static void EnsureAvailable()
    {
        try
        {
            if (NativeMethods.AbiVersion() != 1)
            {
                throw new NativeProtocolUnavailableException("The native protocol ABI version is incompatible.");
            }
        }
        catch (DllNotFoundException exception)
        {
            throw new NativeProtocolUnavailableException(
                "halo_protocol.dll was not found next to the application. Run scripts/build-native.ps1 first.",
                exception);
        }
        catch (BadImageFormatException exception)
        {
            throw new NativeProtocolUnavailableException(
                "halo_protocol.dll has an incompatible architecture.",
                exception);
        }
    }

    private static IntPtr Resolve(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (!string.Equals(libraryName, BaseName, StringComparison.Ordinal))
        {
            return IntPtr.Zero;
        }

        var fileName = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            ? "halo_protocol.dll"
            : RuntimeInformation.IsOSPlatform(OSPlatform.OSX)
                ? "libhalo_protocol.dylib"
                : "libhalo_protocol.so";
        var localPath = Path.Combine(AppContext.BaseDirectory, fileName);
        return NativeLibrary.TryLoad(localPath, out var handle) ? handle : IntPtr.Zero;
    }
}

public sealed class NativeProtocolUnavailableException : InvalidOperationException
{
    public NativeProtocolUnavailableException(string message)
        : base(message)
    {
    }

    public NativeProtocolUnavailableException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

using System.Security.Cryptography;
using System.Text.Json;
using HaloVPN.Protocol.Interop;

namespace HaloVPN.Platform.Windows;

public sealed record DeviceKeyMaterial(byte[] PrivateKey, byte[] PublicKey) : IDisposable
{
    public void Dispose() => CryptographicOperations.ZeroMemory(PrivateKey);
}

public sealed class DeviceKeyStore(string path)
{
    private static readonly byte[] Entropy = "HaloVPN.DeviceKey.v1"u8.ToArray();

    public async Task<DeviceKeyMaterial> LoadOrCreateAsync(CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("DPAPI device key storage requires Windows.");
        }

        if (File.Exists(path))
        {
            var container = JsonSerializer.Deserialize<KeyContainer>(await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false))
                ?? throw new InvalidDataException("Device key container is invalid.");
            var protectedPrivate = Convert.FromBase64String(container.ProtectedPrivateKey);
            try
            {
                var privateKey = ProtectedData.Unprotect(protectedPrivate, Entropy, DataProtectionScope.LocalMachine);
                var publicKey = Convert.FromBase64String(container.PublicKey);
                if (privateKey.Length != 32 || publicKey.Length != 32)
                {
                    CryptographicOperations.ZeroMemory(privateKey);
                    throw new InvalidDataException("Device key container has invalid key lengths.");
                }

                return new DeviceKeyMaterial(privateKey, publicKey);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(protectedPrivate);
            }
        }

        var pair = NativeProtocolLibrary.GenerateKeyPair();
        try
        {
            var protectedPrivate = ProtectedData.Protect(pair.PrivateKey, Entropy, DataProtectionScope.LocalMachine);
            try
            {
                var container = new KeyContainer(1, Convert.ToBase64String(protectedPrivate), Convert.ToBase64String(pair.PublicKey));
                var directory = Path.GetDirectoryName(Path.GetFullPath(path)) ?? throw new InvalidOperationException("Device key path has no parent.");
                Directory.CreateDirectory(directory);
                await using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough | FileOptions.Asynchronous);
                await JsonSerializer.SerializeAsync(stream, container, cancellationToken: cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(protectedPrivate);
            }

            return new DeviceKeyMaterial(pair.PrivateKey, pair.PublicKey);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(pair.PrivateKey);
            throw;
        }
    }

    private sealed record KeyContainer(int Version, string ProtectedPrivateKey, string PublicKey);
}

public sealed class DpapiTokenStore(string path)
{
    private static readonly byte[] Entropy = "HaloVPN.RefreshToken.v1"u8.ToArray();

    public async Task SaveAsync(string refreshToken, CancellationToken cancellationToken)
    {
        var plaintext = System.Text.Encoding.UTF8.GetBytes(refreshToken);
        try
        {
            var protectedValue = ProtectedData.Protect(plaintext, Entropy, DataProtectionScope.CurrentUser);
            try
            {
                var directory = Path.GetDirectoryName(Path.GetFullPath(path)) ?? throw new InvalidOperationException("Token path has no parent.");
                Directory.CreateDirectory(directory);
                await File.WriteAllBytesAsync(path, protectedValue, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(protectedValue);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public async Task<string?> LoadAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(path))
        {
            return null;
        }

        var protectedValue = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
        try
        {
            var plaintext = ProtectedData.Unprotect(protectedValue, Entropy, DataProtectionScope.CurrentUser);
            try
            {
                return System.Text.Encoding.UTF8.GetString(plaintext);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedValue);
        }
    }

    public void Delete()
    {
        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }
}

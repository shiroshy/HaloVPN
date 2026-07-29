using System.Security.Cryptography;

namespace HaloVPN.Protocol.Interop;

public static class KeyMaterial
{
    public static byte[] ReadPrivateKeyFile(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 32, FileOptions.SequentialScan);
        if (stream.Length != NativeProtocolLibrary.KeySize)
        {
            throw new InvalidDataException("The private key file must contain exactly 32 raw bytes.");
        }

        var key = new byte[NativeProtocolLibrary.KeySize];
        try
        {
            stream.ReadExactly(key);
            return key;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(key);
            throw;
        }
    }

    public static byte[] ParsePublicKey(string text)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(text);
        byte[] value;
        try
        {
            value = text.Length == NativeProtocolLibrary.KeySize * 2
                ? Convert.FromHexString(text)
                : Convert.FromBase64String(text);
        }
        catch (FormatException exception)
        {
            throw new ArgumentException("A public key must be 64 hexadecimal characters or Base64-encoded 32 bytes.", nameof(text), exception);
        }

        if (value.Length != NativeProtocolLibrary.KeySize)
        {
            throw new ArgumentException("An X25519 public key must contain exactly 32 bytes.", nameof(text));
        }

        return value;
    }
}

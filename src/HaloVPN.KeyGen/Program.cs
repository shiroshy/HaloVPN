using System.Security.Cryptography;
using HaloVPN.Protocol.Interop;

namespace HaloVPN.KeyGen;

internal static class Program
{
    public static int Main(string[] args)
    {
        try
        {
            var path = GetOption(args, "--private-key");
            var fullPath = Path.GetFullPath(path);
            var directory = Path.GetDirectoryName(fullPath) ?? throw new ArgumentException("The key path has no parent directory.");
            Directory.CreateDirectory(directory);

            var (privateKey, publicKey) = NativeProtocolLibrary.GenerateKeyPair();
            try
            {
                var options = new FileStreamOptions
                {
                    Mode = FileMode.CreateNew,
                    Access = FileAccess.Write,
                    Share = FileShare.None,
                    Options = FileOptions.WriteThrough,
                };
                if (!OperatingSystem.IsWindows())
                {
                    options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
                }

                using (var stream = new FileStream(fullPath, options))
                {
                    stream.Write(privateKey);
                    stream.Flush(true);
                }

                Console.WriteLine($"Private key created: {fullPath}");
                Console.WriteLine($"Public key (Base64): {Convert.ToBase64String(publicKey)}");
                return 0;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(privateKey);
            }
        }
        catch (Exception exception) when (exception is ArgumentException or IOException or UnauthorizedAccessException or NativeProtocolException or NativeProtocolUnavailableException)
        {
            Console.Error.WriteLine($"Key generation failed: {exception.Message}");
            Console.Error.WriteLine("Usage: HaloVPN.KeyGen --private-key <new-file-path>");
            return 2;
        }
    }

    private static string GetOption(string[] args, string name)
    {
        for (var index = 0; index < args.Length - 1; index++)
        {
            if (string.Equals(args[index], name, StringComparison.Ordinal))
            {
                return args[index + 1];
            }
        }

        throw new ArgumentException($"Missing required option {name}.");
    }
}

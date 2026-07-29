using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using Microsoft.Extensions.Options;

namespace HaloVPN.Infrastructure;

public interface IPasswordHasher
{
    string Hash(string password);
    bool Verify(string password, string encodedHash);
}

public sealed class Argon2idPasswordHasher(IOptions<Argon2Options> options) : IPasswordHasher
{
    private readonly Argon2Options _options = Validate(options.Value);

    public string Hash(string password)
    {
        ValidatePassword(password);
        var salt = RandomNumberGenerator.GetBytes(_options.SaltSize);
        try
        {
            var hash = Derive(password, salt, _options.MemorySizeKiB, _options.Iterations, _options.DegreeOfParallelism, _options.HashSize);
            try
            {
                return string.Create(
                    CultureInfo.InvariantCulture,
                    $"$argon2id$v=19$m={_options.MemorySizeKiB},t={_options.Iterations},p={_options.DegreeOfParallelism}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(hash);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(salt);
        }
    }

    public bool Verify(string password, string encodedHash)
    {
        if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(encodedHash))
        {
            return false;
        }

        try
        {
            var parts = encodedHash.Split('$', StringSplitOptions.None);
            if (parts.Length != 6 || parts[1] != "argon2id" || parts[2] != "v=19")
            {
                return false;
            }

            var parameters = parts[3].Split(',');
            if (parameters.Length != 3 ||
                !int.TryParse(parameters[0].AsSpan(2), CultureInfo.InvariantCulture, out var memory) ||
                !int.TryParse(parameters[1].AsSpan(2), CultureInfo.InvariantCulture, out var iterations) ||
                !int.TryParse(parameters[2].AsSpan(2), CultureInfo.InvariantCulture, out var parallelism) ||
                memory is < 8192 or > 1_048_576 || iterations is < 1 or > 20 || parallelism is < 1 or > 16)
            {
                return false;
            }

            var salt = Convert.FromBase64String(parts[4]);
            var expected = Convert.FromBase64String(parts[5]);
            if (salt.Length is < 16 or > 64 || expected.Length is < 16 or > 64)
            {
                return false;
            }

            try
            {
                var actual = Derive(password, salt, memory, iterations, parallelism, expected.Length);
                try
                {
                    return CryptographicOperations.FixedTimeEquals(actual, expected);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(actual);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(salt);
                CryptographicOperations.ZeroMemory(expected);
            }
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static byte[] Derive(string password, byte[] salt, int memory, int iterations, int parallelism, int hashSize)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(password);
        try
        {
            using var argon = new Argon2id(passwordBytes)
            {
                Salt = salt,
                MemorySize = memory,
                Iterations = iterations,
                DegreeOfParallelism = parallelism,
            };
            return argon.GetBytes(hashSize);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    private static void ValidatePassword(string password)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(password);
        if (password.Length is < 12 or > 1024)
        {
            throw new ArgumentException("Password length must be between 12 and 1024 characters.", nameof(password));
        }
    }

    private static Argon2Options Validate(Argon2Options value)
    {
        if (value.MemorySizeKiB is < 8192 or > 1_048_576 || value.Iterations is < 1 or > 20 ||
            value.DegreeOfParallelism is < 1 or > 16 || value.SaltSize is < 16 or > 64 || value.HashSize is < 16 or > 64)
        {
            throw new InvalidOperationException("Argon2id options are outside supported bounds.");
        }

        return value;
    }
}

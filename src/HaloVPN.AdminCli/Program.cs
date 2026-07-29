using HaloVPN.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace HaloVPN.AdminCli;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        try
        {
            var connectionString = Environment.GetEnvironmentVariable("HALOVPN_DATABASE");
            if (string.IsNullOrWhiteSpace(connectionString))
            {
                throw new InvalidOperationException("HALOVPN_DATABASE is required.");
            }

            var dbOptions = new DbContextOptionsBuilder<HaloVpnDbContext>()
                .UseNpgsql(connectionString)
                .UseSnakeCaseNamingConvention()
                .Options;
            await using var dbContext = new HaloVpnDbContext(dbOptions);
            var hasher = new Argon2idPasswordHasher(Options.Create(new Argon2Options()));
            var service = new AdminService(dbContext, hasher, TimeProvider.System);
            return await ExecuteAsync(args, dbContext, service, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or IOException or DbUpdateException)
        {
            Console.Error.WriteLine($"Admin command failed: {exception.Message}");
            PrintUsage();
            return 2;
        }
    }

    private static async Task<int> ExecuteAsync(
        string[] args,
        HaloVpnDbContext dbContext,
        AdminService service,
        CancellationToken cancellationToken)
    {
        if (args.Length < 2)
        {
            throw new ArgumentException("A resource and command are required.");
        }

        switch (args[0], args[1])
        {
            case ("database", "migrate"):
                {
                    RequireLength(args, 2, 2);
                    await dbContext.Database.MigrateAsync(cancellationToken).ConfigureAwait(false);
                    Console.WriteLine("PostgreSQL migrations applied.");
                    break;
                }
            case ("user", "create"):
                {
                    RequireLength(args, 3, 4);
                    var maxDevices = args.Length == 4 ? int.Parse(args[3], System.Globalization.CultureInfo.InvariantCulture) : 1;
                    var password = ReadConfirmedPassword();
                    var user = await service.CreateUserAsync(args[2], password, maxDevices, cancellationToken).ConfigureAwait(false);
                    Console.WriteLine($"Created user id={user.Id:D} username={user.Username} max_devices={user.MaxDevices}");
                    break;
                }
            case ("user", "list"):
                {
                    RequireLength(args, 2, 2);
                    var users = await service.ListUsersAsync(cancellationToken).ConfigureAwait(false);
                    foreach (var user in users)
                    {
                        Console.WriteLine($"{user.Id:D}\t{user.Username}\t{user.Status}\tmax_devices={user.MaxDevices}");
                    }

                    break;
                }
            case ("user", "enable"):
            case ("user", "disable"):
                {
                    RequireLength(args, 3, 3);
                    await service.SetEnabledAsync(args[2], args[1] == "enable", cancellationToken).ConfigureAwait(false);
                    Console.WriteLine($"User {args[2]} is now {(args[1] == "enable" ? "enabled" : "disabled")}");
                    break;
                }
            case ("user", "reset-password"):
                {
                    RequireLength(args, 3, 3);
                    await service.ResetPasswordAsync(args[2], ReadConfirmedPassword(), cancellationToken).ConfigureAwait(false);
                    Console.WriteLine($"Password reset for user {args[2]}; refresh tokens revoked");
                    break;
                }
            case ("device", "list"):
                {
                    RequireLength(args, 3, 3);
                    var devices = await service.ListDevicesAsync(args[2], cancellationToken).ConfigureAwait(false);
                    foreach (var device in devices)
                    {
                        Console.WriteLine($"{device.Id:D}\t{device.Name}\t{device.AssignedTunnelIp}\t{device.Status}");
                    }

                    break;
                }
            case ("device", "revoke"):
                {
                    RequireLength(args, 3, 3);
                    await service.RevokeDeviceAsync(Guid.Parse(args[2]), cancellationToken).ConfigureAwait(false);
                    Console.WriteLine($"Device {args[2]} revoked");
                    break;
                }
            case ("token", "revoke-all"):
                {
                    RequireLength(args, 3, 3);
                    var normalized = HaloVPN.Contracts.UsernameNormalizer.Normalize(args[2]);
                    var user = await dbContext.Users.SingleOrDefaultAsync(value => value.NormalizedUsername == normalized, cancellationToken).ConfigureAwait(false)
                        ?? throw new DomainRuleException("user_not_found", "User does not exist.");
                    var now = DateTimeOffset.UtcNow;
                    var tokens = await dbContext.RefreshTokens.Where(value => value.UserId == user.Id && value.RevokedAt == null).ToListAsync(cancellationToken).ConfigureAwait(false);
                    foreach (var token in tokens)
                    {
                        token.RevokedAt = now;
                    }
                    dbContext.AuditEvents.Add(new AuditEventEntity { UserId = user.Id, EventType = "token_revoke_all", CreatedAt = now });
                    await dbContext.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
                    Console.WriteLine($"All refresh tokens revoked for user {user.Username}");
                    break;
                }
            default:
                throw new ArgumentException("Unknown admin command.");
        }

        return 0;
    }

    private static string ReadConfirmedPassword()
    {
        var first = ReadPassword("Password: ");
        var second = ReadPassword("Confirm password: ");
        if (!string.Equals(first, second, StringComparison.Ordinal))
        {
            throw new ArgumentException("Passwords do not match.");
        }

        return first;
    }

    private static string ReadPassword(string prompt)
    {
        Console.Error.Write(prompt);
        if (Console.IsInputRedirected)
        {
            return Console.ReadLine() ?? throw new EndOfStreamException("Password was not provided on stdin.");
        }

        var characters = new List<char>(128);
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.Error.WriteLine();
                return new string([.. characters]);
            }

            if (key.Key == ConsoleKey.Backspace && characters.Count > 0)
            {
                characters.RemoveAt(characters.Count - 1);
            }
            else if (!char.IsControl(key.KeyChar) && characters.Count < 1024)
            {
                characters.Add(key.KeyChar);
            }
        }
    }

    private static void RequireLength(string[] args, int minimum, int maximum)
    {
        if (args.Length < minimum || args.Length > maximum)
        {
            throw new ArgumentException("The command has an invalid number of arguments.");
        }
    }

    private static void PrintUsage()
    {
        Console.Error.WriteLine("Commands:");
        Console.Error.WriteLine("  database migrate");
        Console.Error.WriteLine("  user create <username> [max-devices]");
        Console.Error.WriteLine("  user list");
        Console.Error.WriteLine("  user enable|disable|reset-password <username>");
        Console.Error.WriteLine("  device list <username>");
        Console.Error.WriteLine("  device revoke <device-id>");
        Console.Error.WriteLine("  token revoke-all <username>");
        Console.Error.WriteLine("Passwords are read interactively or as two lines from redirected stdin.");
    }
}

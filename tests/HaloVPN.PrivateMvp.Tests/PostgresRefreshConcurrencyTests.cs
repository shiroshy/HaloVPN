using HaloVPN.Contracts;
using HaloVPN.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace HaloVPN.PrivateMvp.Tests;

public sealed class PostgresRefreshConcurrencyTests
{
    [Fact]
    [Trait("Category", "PostgreSQL")]
    public async Task ParallelRefreshCreatesAtMostOneChildAndRevokesFamilyOnReuse()
    {
        var connectionString = Environment.GetEnvironmentVariable("HALOVPN_POSTGRES_TEST");
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            return;
        }

        var options = new DbContextOptionsBuilder<HaloVpnDbContext>()
            .UseNpgsql(connectionString)
            .UseSnakeCaseNamingConvention()
            .Options;
        await using (var setup = new HaloVpnDbContext(options))
        {
            await setup.Database.MigrateAsync();
            await setup.AuditEvents.ExecuteDeleteAsync();
            await setup.RefreshTokens.ExecuteDeleteAsync();
            await setup.Devices.ExecuteDeleteAsync();
            await setup.Users.ExecuteDeleteAsync();
            await setup.VpnNodes.ExecuteDeleteAsync();
            var hasher = CreateHasher();
            await new AdminService(setup, hasher, TimeProvider.System)
                .CreateUserAsync("refresh-race", "Test-only concurrency pass!", 1, default);
        }

        AuthTokensResponse original;
        await using (var loginContext = new HaloVpnDbContext(options))
        {
            original = await CreateAuthService(loginContext).LoginAsync("refresh-race", "Test-only concurrency pass!", default);
        }

        var first = RefreshWithNewContextAsync(options, original.RefreshToken);
        var second = RefreshWithNewContextAsync(options, original.RefreshToken);
        var results = await Task.WhenAll(first, second);
        Assert.Single(results, value => value.Tokens is not null);
        Assert.Single(results, value => value.ErrorCode == "refresh_token_reused");

        await using var verification = new HaloVpnDbContext(options);
        var family = await verification.RefreshTokens.OrderBy(value => value.CreatedAt).ToListAsync();
        Assert.Equal(2, family.Count);
        Assert.Single(family, value => value.ReplacedByTokenId.HasValue);
        Assert.All(family, value => Assert.NotNull(value.RevokedAt));
        Assert.DoesNotContain(family, value => value.RevokedAt == null);
        var replacement = Assert.Single(results, value => value.Tokens is not null).Tokens!;
        var rejected = await Assert.ThrowsAsync<DomainRuleException>(() => CreateAuthService(verification).RefreshAsync(replacement.RefreshToken, default));
        Assert.Equal("refresh_token_reused", rejected.Code);
    }

    private static async Task<RefreshResult> RefreshWithNewContextAsync(DbContextOptions<HaloVpnDbContext> options, string token)
    {
        await using var context = new HaloVpnDbContext(options);
        try
        {
            return new RefreshResult(await CreateAuthService(context).RefreshAsync(token, default), null);
        }
        catch (DomainRuleException exception)
        {
            return new RefreshResult(null, exception.Code);
        }
    }

    private static AuthService CreateAuthService(HaloVpnDbContext context)
    {
        var issuer = new TokenIssuer(context, Options.Create(new TokenOptions
        {
            Issuer = "HaloVPN.Postgres.Tests",
            Audience = "HaloVPN.Postgres.Tests",
            SigningKeyBase64 = Convert.ToBase64String(Enumerable.Repeat((byte)0xB4, 32).ToArray()),
        }), TimeProvider.System);
        return new AuthService(context, CreateHasher(), issuer, TimeProvider.System);
    }

    private static Argon2idPasswordHasher CreateHasher() => new(Options.Create(new Argon2Options
    {
        MemorySizeKiB = 8192,
        Iterations = 1,
        DegreeOfParallelism = 1,
    }));

    private sealed record RefreshResult(AuthTokensResponse? Tokens, string? ErrorCode);
}

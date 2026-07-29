using System.Net;
using HaloVPN.Contracts;
using HaloVPN.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace HaloVPN.PrivateMvp.Tests;

public sealed class AuthAndDeviceTests
{
    [Fact]
    public async Task UserLifecycleAndPasswordAuthenticationAreEnforced()
    {
        await using var fixture = TestFixture.Create();
        await fixture.Admin.CreateUserAsync(" Alice ", "Correct horse battery!", 1, default);
        var user = Assert.Single(await fixture.Admin.ListUsersAsync(default));
        Assert.Equal("ALICE", user.NormalizedUsername);
        await Assert.ThrowsAsync<DomainRuleException>(() => fixture.Admin.CreateUserAsync("alice", "Another strong password!", 1, default));

        var tokens = await fixture.Auth.LoginAsync("aLiCe", "Correct horse battery!", default);
        Assert.False(string.IsNullOrWhiteSpace(tokens.AccessToken));
        await Assert.ThrowsAsync<DomainRuleException>(() => fixture.Auth.LoginAsync("Alice", "wrong password value", default));

        await fixture.Admin.SetEnabledAsync("Alice", false, default);
        await Assert.ThrowsAsync<DomainRuleException>(() => fixture.Auth.LoginAsync("Alice", "Correct horse battery!", default));
        await fixture.Admin.SetEnabledAsync("Alice", true, default);
        await fixture.Admin.ResetPasswordAsync("Alice", "Replacement password!", default);
        await Assert.ThrowsAsync<DomainRuleException>(() => fixture.Auth.LoginAsync("Alice", "Correct horse battery!", default));
        Assert.NotNull(await fixture.Auth.LoginAsync("Alice", "Replacement password!", default));
    }

    [Fact]
    public async Task RefreshRotationReuseLogoutAndRevokeAllAreEnforced()
    {
        await using var fixture = TestFixture.Create();
        await fixture.Admin.CreateUserAsync("token-user", "Correct horse battery!", 1, default);
        var first = await fixture.Auth.LoginAsync("token-user", "Correct horse battery!", default);
        var second = await fixture.Auth.RefreshAsync(first.RefreshToken, default);
        var reuse = await Assert.ThrowsAsync<DomainRuleException>(() => fixture.Auth.RefreshAsync(first.RefreshToken, default));
        Assert.Equal("refresh_token_reused", reuse.Code);
        await Assert.ThrowsAsync<DomainRuleException>(() => fixture.Auth.RefreshAsync(second.RefreshToken, default));

        var logoutToken = await fixture.Auth.LoginAsync("token-user", "Correct horse battery!", default);
        await fixture.Auth.LogoutAsync(logoutToken.RefreshToken, default);
        await Assert.ThrowsAsync<DomainRuleException>(() => fixture.Auth.RefreshAsync(logoutToken.RefreshToken, default));

        var revoked = await fixture.Auth.LoginAsync("token-user", "Correct horse battery!", default);
        var user = await fixture.Db.Users.SingleAsync();
        await fixture.Auth.RevokeAllAsync(user.Id, default);
        await Assert.ThrowsAsync<DomainRuleException>(() => fixture.Auth.RefreshAsync(revoked.RefreshToken, default));
    }

    [Fact]
    public async Task DeviceRegistrationAllocatesUniqueLeasesAndHonorsLimitsAndRevocation()
    {
        await using var fixture = TestFixture.Create();
        await fixture.Admin.CreateUserAsync("first-user", "Correct horse battery!", 1, default);
        await fixture.Admin.CreateUserAsync("second-user", "Correct horse battery!", 1, default);
        var users = await fixture.Db.Users.OrderBy(value => value.Username).ToListAsync();
        var firstKey = Enumerable.Repeat((byte)1, 32).ToArray();
        var secondKey = Enumerable.Repeat((byte)2, 32).ToArray();
        var first = await fixture.Devices.RegisterAsync(users[0].Id, "PC-1", firstKey, default);
        var firstAgain = await fixture.Devices.RegisterAsync(users[0].Id, "PC-1", firstKey, default);
        Assert.Equal(first.DeviceId, firstAgain.DeviceId);
        var second = await fixture.Devices.RegisterAsync(users[1].Id, "PC-2", secondKey, default);
        Assert.NotEqual(first.Profile.AssignedClientIpv4, second.Profile.AssignedClientIpv4);
        Assert.Equal(24, first.Profile.TunnelPrefixLength);

        await Assert.ThrowsAsync<DomainRuleException>(() => fixture.Devices.RegisterAsync(users[0].Id, "PC-extra", Enumerable.Repeat((byte)3, 32).ToArray(), default));
        await Assert.ThrowsAsync<DomainRuleException>(() => fixture.Devices.RegisterAsync(users[1].Id, "stolen", firstKey, default));
        Assert.Equal(first.DeviceId, (await fixture.Devices.GetProfileAsync(users[0].Id, first.DeviceId, default)).DeviceId);
        await Assert.ThrowsAsync<DomainRuleException>(() => fixture.Devices.GetProfileAsync(users[1].Id, first.DeviceId, default));
        await fixture.Devices.RevokeAsync(users[0].Id, first.DeviceId, default);
        await Assert.ThrowsAsync<DomainRuleException>(() => fixture.Devices.GetProfileAsync(users[0].Id, first.DeviceId, default));
    }

    [Fact]
    public async Task SmallAddressPoolFailsClosedWhenExhausted()
    {
        await using var fixture = TestFixture.Create("10.88.0.0/30", "10.88.0.1");
        await fixture.Admin.CreateUserAsync("pool-one", "Correct horse battery!", 1, default);
        await fixture.Admin.CreateUserAsync("pool-two", "Correct horse battery!", 1, default);
        var users = await fixture.Db.Users.OrderBy(value => value.Username).ToListAsync();
        await fixture.Devices.RegisterAsync(users[0].Id, "one", Enumerable.Repeat((byte)7, 32).ToArray(), default);
        var error = await Assert.ThrowsAsync<DomainRuleException>(() => fixture.Devices.RegisterAsync(users[1].Id, "two", Enumerable.Repeat((byte)8, 32).ToArray(), default));
        Assert.Equal("address_pool_exhausted", error.Code);
    }
}

internal sealed class TestFixture : IAsyncDisposable
{
    private TestFixture(HaloVpnDbContext db, Argon2idPasswordHasher hasher, TokenIssuer issuer, VpnNodeSeedOptions nodeOptions)
    {
        Db = db;
        Admin = new AdminService(db, hasher, TimeProvider.System);
        Auth = new AuthService(db, hasher, issuer, TimeProvider.System);
        Devices = new DeviceService(db, issuer, Options.Create(nodeOptions), new LeaseAllocationLock(), TimeProvider.System);
    }

    internal HaloVpnDbContext Db { get; }
    internal AdminService Admin { get; }
    internal AuthService Auth { get; }
    internal DeviceService Devices { get; }

    internal static TestFixture Create(string subnet = "10.77.0.0/24", string gateway = "10.77.0.1")
    {
        var db = new HaloVpnDbContext(new DbContextOptionsBuilder<HaloVpnDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString("N"))
            .Options);
        var nodeOptions = new VpnNodeSeedOptions { TunnelSubnet = subnet, TunnelGateway = gateway };
        db.VpnNodes.Add(new VpnNodeEntity
        {
            Id = Guid.NewGuid(),
            Name = "Astana-1",
            PublicHost = "127.0.0.1",
            PublicKey = new byte[32],
            UdpPort = 45000,
            TunnelSubnet = subnet,
            DnsServers = "1.1.1.1",
            Mtu = 1200,
            Enabled = true,
        });
        db.SaveChanges();
        var hasher = new Argon2idPasswordHasher(Options.Create(new Argon2Options { MemorySizeKiB = 8192, Iterations = 1, DegreeOfParallelism = 1 }));
        var issuer = new TokenIssuer(db, Options.Create(new TokenOptions
        {
            Issuer = "HaloVPN.Tests",
            Audience = "HaloVPN.Tests",
            SigningKeyBase64 = Convert.ToBase64String(Enumerable.Repeat((byte)0xA5, 32).ToArray()),
        }), TimeProvider.System);
        return new TestFixture(db, hasher, issuer, nodeOptions);
    }

    public ValueTask DisposeAsync() => Db.DisposeAsync();
}

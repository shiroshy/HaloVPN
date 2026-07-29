using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using HaloVPN.Contracts;
using HaloVPN.Infrastructure;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace HaloVPN.ControlPlane.Tests;

public sealed class ControlPlaneApiTests
{
    [Fact]
    public async Task PlainHttpIsRejectedOutsideDevelopment()
    {
        await using var factory = new ControlPlaneFactory();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("http://localhost"),
            AllowAutoRedirect = false,
        });
        var response = await client.GetAsync("health/live");
        Assert.Equal((HttpStatusCode)426, response.StatusCode);
    }

    [Fact]
    public async Task LoginRateLimitReturnsTooManyRequestsAfterTenAttempts()
    {
        await using var factory = new ControlPlaneFactory();
        using var client = factory.CreateHttpsClient();
        for (var attempt = 0; attempt < 10; attempt++)
        {
            var response = await client.PostAsJsonAsync("api/auth/login", new LoginRequest("missing", "invalid password value"));
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }

        var limited = await client.PostAsJsonAsync("api/auth/login", new LoginRequest("missing", "invalid password value"));
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
    }

    [Fact]
    public async Task LoginDeviceProfileRefreshAndLogoutFlowUsesDeviceBoundToken()
    {
        await using var factory = new ControlPlaneFactory();
        using (var scope = factory.Services.CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<AdminService>()
                .CreateUserAsync("api-user", "Correct horse battery!", 1, default);
        }

        using var client = factory.CreateHttpsClient();
        var loginResponse = await client.PostAsJsonAsync("api/auth/login", new LoginRequest("API-USER", "Correct horse battery!"));
        Assert.True(loginResponse.IsSuccessStatusCode, await loginResponse.Content.ReadAsStringAsync());
        var login = await loginResponse.Content.ReadFromJsonAsync<AuthTokensResponse>();
        Assert.NotNull(login);

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", login.AccessToken);
        var registrationResponse = await client.PostAsJsonAsync("api/devices/register", new RegisterDeviceRequest("test-device", Convert.ToBase64String(Enumerable.Repeat((byte)4, 32).ToArray())));
        registrationResponse.EnsureSuccessStatusCode();
        var registration = await registrationResponse.Content.ReadFromJsonAsync<DeviceRegistrationResponse>();
        Assert.NotNull(registration);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", registration.Tokens.AccessToken);
        var profile = await client.GetFromJsonAsync<VpnProfileResponse>("api/vpn/profile");
        Assert.Equal(registration.DeviceId, profile!.DeviceId);

        var refreshResponse = await client.PostAsJsonAsync("api/auth/refresh", new RefreshRequest(registration.Tokens.RefreshToken));
        refreshResponse.EnsureSuccessStatusCode();
        var rotated = await refreshResponse.Content.ReadFromJsonAsync<AuthTokensResponse>();
        Assert.NotNull(rotated);
        var logout = await client.PostAsJsonAsync("api/auth/logout", new LogoutRequest(rotated.RefreshToken));
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);
        var rejected = await client.PostAsJsonAsync("api/auth/refresh", new RefreshRequest(rotated.RefreshToken));
        Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
    }
}

internal sealed class ControlPlaneFactory : WebApplicationFactory<Program>
{
    private readonly string _databaseName = Guid.NewGuid().ToString("N");

    static ControlPlaneFactory()
    {
        Environment.SetEnvironmentVariable("HALOVPN_DATABASE", "test-only");
        Environment.SetEnvironmentVariable("Tokens__Issuer", "HaloVPN.Tests");
        Environment.SetEnvironmentVariable("Tokens__Audience", "HaloVPN.Tests");
        Environment.SetEnvironmentVariable("Tokens__SigningKeyBase64", Convert.ToBase64String(Enumerable.Repeat((byte)0xA7, 32).ToArray()));
        Environment.SetEnvironmentVariable("Argon2id__MemorySizeKiB", "8192");
        Environment.SetEnvironmentVariable("Argon2id__Iterations", "1");
        Environment.SetEnvironmentVariable("Argon2id__DegreeOfParallelism", "1");
        Environment.SetEnvironmentVariable("VpnNode__PublicHost", "127.0.0.1");
        Environment.SetEnvironmentVariable("VpnNode__PublicKeyBase64", Convert.ToBase64String(new byte[32]));
        Environment.SetEnvironmentVariable("VpnNode__Mtu", "1200");
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["HALOVPN_DATABASE"] = "test-only",
            ["Tokens:Issuer"] = "HaloVPN.Tests",
            ["Tokens:Audience"] = "HaloVPN.Tests",
            ["Tokens:SigningKeyBase64"] = Convert.ToBase64String(Enumerable.Repeat((byte)0xA7, 32).ToArray()),
            ["Argon2id:MemorySizeKiB"] = "8192",
            ["Argon2id:Iterations"] = "1",
            ["Argon2id:DegreeOfParallelism"] = "1",
            ["VpnNode:PublicHost"] = "127.0.0.1",
            ["VpnNode:PublicKeyBase64"] = Convert.ToBase64String(new byte[32]),
            ["VpnNode:Mtu"] = "1200",
        }));
        builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<DbContextOptions<HaloVpnDbContext>>();
            services.RemoveAll<IDbContextOptionsConfiguration<HaloVpnDbContext>>();
            services.RemoveAll<HaloVpnDbContext>();
            services.AddDbContext<HaloVpnDbContext>(options => options.UseInMemoryDatabase(_databaseName));
        });
    }

    internal HttpClient CreateHttpsClient() => CreateClient(new WebApplicationFactoryClientOptions
    {
        BaseAddress = new Uri("https://localhost"),
        AllowAutoRedirect = false,
    });
}

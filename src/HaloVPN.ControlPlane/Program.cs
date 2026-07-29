using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.RateLimiting;
using HaloVPN.Contracts;
using HaloVPN.Infrastructure;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);
var connectionString = builder.Configuration["HALOVPN_DATABASE"] ??
    throw new InvalidOperationException("HALOVPN_DATABASE must contain the PostgreSQL connection string.");

builder.Services.AddDbContext<HaloVpnDbContext>(options =>
    options.UseNpgsql(connectionString).UseSnakeCaseNamingConvention());
builder.Services.Configure<TokenOptions>(builder.Configuration.GetSection(TokenOptions.SectionName));
builder.Services.Configure<Argon2Options>(builder.Configuration.GetSection("Argon2id"));
builder.Services.Configure<VpnNodeSeedOptions>(builder.Configuration.GetSection(VpnNodeSeedOptions.SectionName));
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<LeaseAllocationLock>();
builder.Services.AddScoped<IPasswordHasher, Argon2idPasswordHasher>();
builder.Services.AddScoped<ITokenIssuer, TokenIssuer>();
builder.Services.AddScoped<AuthService>();
builder.Services.AddScoped<DeviceService>();
builder.Services.AddScoped<AdminService>();
builder.Services.AddScoped<INodeAuthorizationRepository, PostgresNodeAuthorizationRepository>();

var tokenOptions = builder.Configuration.GetSection(TokenOptions.SectionName).Get<TokenOptions>() ??
    throw new InvalidOperationException("Tokens configuration is required.");
var signingKey = DecodeSigningKey(tokenOptions.SigningKeyBase64);
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
{
    options.MapInboundClaims = false;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidIssuer = tokenOptions.Issuer,
        ValidateAudience = true,
        ValidAudience = tokenOptions.Audience,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(signingKey),
        ValidateLifetime = true,
        ClockSkew = TimeSpan.FromSeconds(30),
        NameClaimType = JwtRegisteredClaimNames.UniqueName,
    };
});
builder.Services.AddAuthorization();
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("login", context => RateLimitPartition.GetFixedWindowLimiter(
        context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 10,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
            AutoReplenishment = true,
        }));
});
builder.Services.AddHealthChecks().AddDbContextCheck<HaloVpnDbContext>("postgresql", HealthStatus.Unhealthy);

var app = builder.Build();
if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
    app.Use(async (context, next) =>
    {
        if (!context.Request.IsHttps)
        {
            context.Response.StatusCode = StatusCodes.Status426UpgradeRequired;
            await context.Response.WriteAsJsonAsync(
                new ApiErrorResponse("https_required", "HTTPS is required."),
                context.RequestAborted).ConfigureAwait(false);
            return;
        }

        await next(context).ConfigureAwait(false);
    });
}

app.UseExceptionHandler(errorApp => errorApp.Run(async context =>
{
    var exception = context.Features.Get<Microsoft.AspNetCore.Diagnostics.IExceptionHandlerFeature>()?.Error;
    var (status, code, message) = exception switch
    {
        DomainRuleException domain => (StatusCodes.Status400BadRequest, domain.Code, domain.Message),
        _ => (StatusCodes.Status500InternalServerError, "internal_error", "The request failed."),
    };
    context.Response.StatusCode = status;
    await context.Response.WriteAsJsonAsync(new ApiErrorResponse(code, message), context.RequestAborted).ConfigureAwait(false);
}));
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/api/auth/login", async (LoginRequest request, AuthService service, CancellationToken cancellationToken) =>
    Results.Ok(await service.LoginAsync(request.Username, request.Password, cancellationToken).ConfigureAwait(false)))
    .RequireRateLimiting("login");

app.MapPost("/api/auth/refresh", async (RefreshRequest request, AuthService service, CancellationToken cancellationToken) =>
    Results.Ok(await service.RefreshAsync(request.RefreshToken, cancellationToken).ConfigureAwait(false)))
    .RequireRateLimiting("login");

app.MapPost("/api/auth/logout", async (LogoutRequest request, AuthService service, CancellationToken cancellationToken) =>
{
    await service.LogoutAsync(request.RefreshToken, cancellationToken).ConfigureAwait(false);
    return Results.NoContent();
});

var devices = app.MapGroup("/api/devices").RequireAuthorization();
devices.MapPost("/register", async (RegisterDeviceRequest request, ClaimsPrincipal principal, DeviceService service, CancellationToken cancellationToken) =>
{
    var userId = RequiredGuidClaim(principal, JwtRegisteredClaimNames.Sub);
    byte[] publicKey;
    try
    {
        publicKey = Convert.FromBase64String(request.NoisePublicKey);
    }
    catch (FormatException)
    {
        throw new DomainRuleException("invalid_device_key", "Noise public key is not valid Base64.");
    }

    if (publicKey.Length != 32)
    {
        throw new DomainRuleException("invalid_device_key", "Noise public key must contain exactly 32 bytes.");
    }

    return Results.Ok(await service.RegisterAsync(userId, request.Name, publicKey, cancellationToken).ConfigureAwait(false));
});
devices.MapGet("/", async (ClaimsPrincipal principal, DeviceService service, CancellationToken cancellationToken) =>
    Results.Ok(await service.ListAsync(RequiredGuidClaim(principal, JwtRegisteredClaimNames.Sub), cancellationToken).ConfigureAwait(false)));
devices.MapDelete("/{id:guid}", async (Guid id, ClaimsPrincipal principal, DeviceService service, CancellationToken cancellationToken) =>
{
    await service.RevokeAsync(RequiredGuidClaim(principal, JwtRegisteredClaimNames.Sub), id, cancellationToken).ConfigureAwait(false);
    return Results.NoContent();
});

app.MapGet("/api/vpn/profile", async (ClaimsPrincipal principal, DeviceService service, CancellationToken cancellationToken) =>
{
    var userId = RequiredGuidClaim(principal, JwtRegisteredClaimNames.Sub);
    var deviceId = RequiredGuidClaim(principal, "device_id");
    return Results.Ok(await service.GetProfileAsync(userId, deviceId, cancellationToken).ConfigureAwait(false));
}).RequireAuthorization();

app.MapHealthChecks("/health/live", new HealthCheckOptions { Predicate = _ => false });
app.MapHealthChecks("/health/ready", new HealthCheckOptions { Predicate = _ => true });

await InitializeDatabaseAsync(app.Services, app.Logger, app.Lifetime.ApplicationStopping).ConfigureAwait(false);
await app.RunAsync().ConfigureAwait(false);

static byte[] DecodeSigningKey(string encoded)
{
    try
    {
        var key = Convert.FromBase64String(encoded);
        if (key.Length < 32)
        {
            throw new InvalidOperationException("Token signing key must contain at least 32 random bytes.");
        }

        return key;
    }
    catch (FormatException exception)
    {
        throw new InvalidOperationException("Token signing key must be Base64.", exception);
    }
}

static Guid RequiredGuidClaim(ClaimsPrincipal principal, string claimType)
{
    var value = principal.FindFirstValue(claimType);
    return Guid.TryParse(value, out var id)
        ? id
        : throw new DomainRuleException("invalid_access_token", $"Required claim {claimType} is absent.");
}

static async Task InitializeDatabaseAsync(IServiceProvider services, ILogger logger, CancellationToken cancellationToken)
{
    await using var scope = services.CreateAsyncScope();
    var dbContext = scope.ServiceProvider.GetRequiredService<HaloVpnDbContext>();
    var environment = scope.ServiceProvider.GetRequiredService<IHostEnvironment>();
    if (environment.IsEnvironment("Testing"))
    {
        await dbContext.Database.EnsureCreatedAsync(cancellationToken).ConfigureAwait(false);
    }
    else
    {
        await dbContext.Database.MigrateAsync(cancellationToken).ConfigureAwait(false);
    }
    if (await dbContext.VpnNodes.AnyAsync(cancellationToken).ConfigureAwait(false))
    {
        return;
    }

    var options = scope.ServiceProvider.GetRequiredService<IOptions<VpnNodeSeedOptions>>().Value;
    if (string.IsNullOrWhiteSpace(options.PublicHost) || string.IsNullOrWhiteSpace(options.PublicKeyBase64))
    {
        logger.LogWarning("VPN node seed was skipped because PublicHost or PublicKeyBase64 is not configured");
        return;
    }

    byte[] publicKey;
    try
    {
        publicKey = Convert.FromBase64String(options.PublicKeyBase64);
    }
    catch (FormatException exception)
    {
        throw new InvalidOperationException("VpnNode public key is not valid Base64.", exception);
    }

    if (publicKey.Length != 32)
    {
        throw new InvalidOperationException("VpnNode public key must contain exactly 32 bytes.");
    }

    _ = Ipv4Subnet.Parse(options.TunnelSubnet);
    _ = System.Net.IPAddress.Parse(options.TunnelGateway);
    dbContext.VpnNodes.Add(new VpnNodeEntity
    {
        Id = Guid.NewGuid(),
        Name = options.Name,
        PublicHost = options.PublicHost,
        PublicKey = publicKey,
        UdpPort = options.UdpPort,
        TunnelSubnet = options.TunnelSubnet,
        DnsServers = string.Join(',', options.DnsServers),
        Mtu = options.Mtu,
        Enabled = true,
    });
    await dbContext.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    logger.LogInformation("Seeded VPN node {NodeName}", options.Name);
}

public partial class Program;

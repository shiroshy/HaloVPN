using HaloVPN.Infrastructure;
using HaloVPN.Node;
using HaloVPN.Node.Core;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;

var builder = Host.CreateApplicationBuilder(args);
var connectionString = builder.Configuration["HALOVPN_DATABASE"] ??
    throw new InvalidOperationException("HALOVPN_DATABASE must contain a read-only PostgreSQL connection string.");
builder.Services.Configure<NodeOptions>(builder.Configuration.GetSection(NodeOptions.SectionName));
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddPooledDbContextFactory<HaloVpnDbContext>(options =>
    options.UseNpgsql(connectionString).UseSnakeCaseNamingConvention());
builder.Services.AddSingleton<INodeAuthorizationRepository, FactoryNodeAuthorizationRepository>();
builder.Services.AddSingleton(provider =>
{
    var options = provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<NodeOptions>>().Value;
    return new NodeSessionOptions
    {
        MaximumActiveSessions = options.MaximumActiveSessions,
        MaximumPendingHandshakes = options.MaximumPendingHandshakes,
        MaximumPendingPerSource = options.MaximumPendingPerSource,
        MaximumAttemptsPerSourceWindow = options.MaximumAttemptsPerSourceWindow,
        AttemptWindow = options.HandshakeAttemptWindow,
        IdleTimeout = options.IdleTimeout,
    };
});
builder.Services.AddSingleton(provider => new AuthorizationCacheOptions
{
    MaximumDevices = provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<NodeOptions>>().Value.MaximumCachedDevices,
    RefreshInterval = provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<NodeOptions>>().Value.AuthorizationRefreshInterval,
    MaximumStaleAge = provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<NodeOptions>>().Value.MaximumAuthorizationStaleAge,
});
builder.Services.AddSingleton<AuthorizationCache>();
builder.Services.AddSingleton<NodeSessionRegistry>();
builder.Services.AddSingleton<NodeHandshakeRateLimiter>();
builder.Services.AddSingleton(provider =>
{
    var options = provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<NodeOptions>>().Value;
    return new HandshakeResponseCache(new HandshakeResponseCacheOptions
    {
        MaximumEntries = options.MaximumHandshakeResponseCacheEntries,
        MaximumEntriesPerSource = options.MaximumHandshakeResponseCacheEntriesPerSource,
        TimeToLive = options.HandshakeResponseCacheTtl,
    });
});
builder.Services.AddSingleton<NodeHandshakeCoordinator>();
builder.Services.AddHostedService<NodeWorker>();

await builder.Build().RunAsync().ConfigureAwait(false);

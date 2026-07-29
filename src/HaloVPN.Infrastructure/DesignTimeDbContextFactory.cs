using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace HaloVPN.Infrastructure;

public sealed class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<HaloVpnDbContext>
{
    public HaloVpnDbContext CreateDbContext(string[] args)
    {
        var connectionString = Environment.GetEnvironmentVariable("HALOVPN_DATABASE")
            ?? "Host=localhost;Database=halovpn;Username=halovpn";
        var options = new DbContextOptionsBuilder<HaloVpnDbContext>()
            .UseNpgsql(connectionString)
            .UseSnakeCaseNamingConvention()
            .Options;
        return new HaloVpnDbContext(options);
    }
}

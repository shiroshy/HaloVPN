using System.Net;
using HaloVPN.Contracts;
using Microsoft.EntityFrameworkCore;

namespace HaloVPN.Infrastructure;

public sealed record AuthorizedDevice(Guid DeviceId, byte[] NoisePublicKey, IPAddress AssignedTunnelIp);

public interface INodeAuthorizationRepository
{
    Task<IReadOnlyList<AuthorizedDevice>> GetAuthorizedDevicesAsync(int maximum, CancellationToken cancellationToken);
}

public sealed class PostgresNodeAuthorizationRepository(HaloVpnDbContext dbContext) : INodeAuthorizationRepository
{
    public async Task<IReadOnlyList<AuthorizedDevice>> GetAuthorizedDevicesAsync(int maximum, CancellationToken cancellationToken)
    {
        if (maximum is < 1 or > 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(maximum));
        }

        return await dbContext.Devices.AsNoTracking()
            .Where(value => value.Status == DeviceStatus.Active && value.User.Status == UserStatus.Active)
            .OrderBy(value => value.Id)
            .Take(maximum)
            .Select(value => new AuthorizedDevice(value.Id, value.NoisePublicKey, value.AssignedTunnelIp))
            .ToListAsync(cancellationToken).ConfigureAwait(false);
    }
}

public sealed class FactoryNodeAuthorizationRepository(IDbContextFactory<HaloVpnDbContext> dbContextFactory) : INodeAuthorizationRepository
{
    public async Task<IReadOnlyList<AuthorizedDevice>> GetAuthorizedDevicesAsync(int maximum, CancellationToken cancellationToken)
    {
        await using var dbContext = await dbContextFactory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        return await new PostgresNodeAuthorizationRepository(dbContext)
            .GetAuthorizedDevicesAsync(maximum, cancellationToken).ConfigureAwait(false);
    }
}

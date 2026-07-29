using Microsoft.EntityFrameworkCore;

namespace HaloVPN.Infrastructure;

public sealed class HaloVpnDbContext(DbContextOptions<HaloVpnDbContext> options) : DbContext(options)
{
    public DbSet<UserEntity> Users => Set<UserEntity>();
    public DbSet<DeviceEntity> Devices => Set<DeviceEntity>();
    public DbSet<RefreshTokenEntity> RefreshTokens => Set<RefreshTokenEntity>();
    public DbSet<VpnNodeEntity> VpnNodes => Set<VpnNodeEntity>();
    public DbSet<AuditEventEntity> AuditEvents => Set<AuditEventEntity>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<UserEntity>(entity =>
        {
            entity.ToTable("users");
            entity.HasKey(value => value.Id);
            entity.HasIndex(value => value.NormalizedUsername).IsUnique();
            entity.Property(value => value.Username).HasMaxLength(64);
            entity.Property(value => value.NormalizedUsername).HasMaxLength(64);
            entity.Property(value => value.PasswordHash).HasMaxLength(512);
            entity.Property(value => value.Status).HasConversion<string>().HasMaxLength(16);
            entity.Property(value => value.MaxDevices).HasDefaultValue(1);
        });

        modelBuilder.Entity<DeviceEntity>(entity =>
        {
            entity.ToTable("devices", table => table.HasCheckConstraint(
                "ck_devices_assigned_tunnel_ip_range",
                "assigned_tunnel_ip BETWEEN 0 AND 4294967295"));
            entity.HasKey(value => value.Id);
            entity.HasIndex(value => value.NoisePublicKey).IsUnique();
            entity.HasIndex(value => value.AssignedTunnelIp).IsUnique();
            entity.Property(value => value.Name).HasMaxLength(80);
            entity.Property(value => value.NoisePublicKey).HasColumnType("bytea");
            entity.Property(value => value.AssignedTunnelIp)
                .HasConversion(
                    value => (long)Ipv4Subnet.ToUInt32(value),
                    value => Ipv4Subnet.FromUInt32(checked((uint)value)))
                .HasColumnType("bigint");
            entity.Property(value => value.Status).HasConversion<string>().HasMaxLength(16);
            entity.HasOne(value => value.User).WithMany(value => value.Devices).HasForeignKey(value => value.UserId).OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<RefreshTokenEntity>(entity =>
        {
            entity.ToTable("refresh_tokens");
            entity.HasKey(value => value.Id);
            entity.HasIndex(value => value.TokenHash).IsUnique();
            entity.HasIndex(value => value.FamilyId);
            entity.Property(value => value.TokenHash).HasColumnType("bytea");
            entity.HasOne(value => value.User).WithMany(value => value.RefreshTokens).HasForeignKey(value => value.UserId).OnDelete(DeleteBehavior.Cascade);
            entity.HasOne(value => value.Device).WithMany(value => value.RefreshTokens).HasForeignKey(value => value.DeviceId).OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<VpnNodeEntity>(entity =>
        {
            entity.ToTable("vpn_nodes");
            entity.HasKey(value => value.Id);
            entity.HasIndex(value => value.Name).IsUnique();
            entity.Property(value => value.Name).HasMaxLength(80);
            entity.Property(value => value.PublicKey).HasColumnType("bytea");
            entity.Property(value => value.PublicHost).HasMaxLength(255);
            entity.Property(value => value.TunnelSubnet).HasMaxLength(32);
            entity.Property(value => value.DnsServers).HasMaxLength(512);
        });

        modelBuilder.Entity<AuditEventEntity>(entity =>
        {
            entity.ToTable("audit_events");
            entity.HasKey(value => value.Id);
            entity.HasIndex(value => value.CreatedAt);
            entity.Property(value => value.EventType).HasMaxLength(64);
            entity.Property(value => value.SafeDetail).HasMaxLength(256);
        });
    }
}

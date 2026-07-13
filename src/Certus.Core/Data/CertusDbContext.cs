using Certus.Core.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace Certus.Core.Data;

/// <summary>
/// Entity Framework Core database context for Certus.
/// Uses SQLite as the embedded database.
/// </summary>
public class CertusDbContext : DbContext
{
    public CertusDbContext(DbContextOptions<CertusDbContext> options)
        : base(options)
    {
    }

    // Phase 2: ACME accounts
    public DbSet<AcmeAccount> AcmeAccounts => Set<AcmeAccount>();

    // Phase 3: ACME orders, authorizations, challenges, certificates
    public DbSet<AcmeOrder> AcmeOrders => Set<AcmeOrder>();
    public DbSet<AcmeAuthorization> AcmeAuthorizations => Set<AcmeAuthorization>();
    public DbSet<AcmeChallenge> AcmeChallenges => Set<AcmeChallenge>();
    public DbSet<AcmeCertificate> AcmeCertificates => Set<AcmeCertificate>();

    // Phase 5: Synced certificate inventory from ADCS CA database
    public DbSet<SyncedCertificate> SyncedCertificates => Set<SyncedCertificate>();

    // Phase 7: Alert deduplication tracking
    public DbSet<AlertSent> AlertsSent => Set<AlertSent>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<AcmeAccount>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.AccountId).IsUnique();
            entity.HasIndex(e => e.JwkThumbprint).IsUnique();
            entity.Property(e => e.AccountId).HasMaxLength(64).IsRequired();
            entity.Property(e => e.JwkThumbprint).HasMaxLength(64).IsRequired();
            entity.Property(e => e.Status).HasMaxLength(20).IsRequired().HasDefaultValue("valid");
        });

        modelBuilder.Entity<AcmeOrder>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.OrderId).IsUnique();
            entity.Property(e => e.OrderId).HasMaxLength(64).IsRequired();
            entity.Property(e => e.Status).HasMaxLength(20).IsRequired().HasDefaultValue("pending");
            entity.Property(e => e.TemplateId).HasMaxLength(200).IsRequired();
            entity.Property(e => e.IdentifiersJson).IsRequired();

            entity.HasOne(e => e.Account)
                .WithMany()
                .HasForeignKey(e => e.AccountId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<AcmeAuthorization>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.AuthorizationId).IsUnique();
            entity.Property(e => e.AuthorizationId).HasMaxLength(64).IsRequired();
            entity.Property(e => e.IdentifierType).HasMaxLength(10).IsRequired();
            entity.Property(e => e.IdentifierValue).HasMaxLength(253).IsRequired();
            entity.Property(e => e.Status).HasMaxLength(20).IsRequired().HasDefaultValue("pending");

            entity.HasOne(e => e.Order)
                .WithMany(o => o.Authorizations)
                .HasForeignKey(e => e.OrderId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<AcmeChallenge>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.ChallengeId).IsUnique();
            entity.HasIndex(e => e.Status); // Indexed for the background validation sweep
            entity.Property(e => e.ChallengeId).HasMaxLength(64).IsRequired();
            entity.Property(e => e.Type).HasMaxLength(20).IsRequired();
            entity.Property(e => e.Token).HasMaxLength(256).IsRequired();
            entity.Property(e => e.Status).HasMaxLength(20).IsRequired().HasDefaultValue("pending");

            entity.HasOne(e => e.Authorization)
                .WithMany(a => a.Challenges)
                .HasForeignKey(e => e.AuthorizationId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<AcmeCertificate>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.CertificateId).IsUnique();
            entity.HasIndex(e => e.SerialNumber); // Looked up by serial during revocation (RFC 8555 §7.6)
            entity.HasIndex(e => e.AdcsRequestId); // Joined from the synced inventory to resolve the ACME contact
            entity.Property(e => e.CertificateId).HasMaxLength(64).IsRequired();
            entity.Property(e => e.CertificatePem).IsRequired();
            entity.Property(e => e.SerialNumber).HasMaxLength(64);

            entity.HasOne(e => e.Order)
                .WithMany()
                .HasForeignKey(e => e.OrderId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<SyncedCertificate>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.RequestId).IsUnique();
            entity.HasIndex(e => e.SerialNumber);
            entity.HasIndex(e => e.NotAfter); // Fast expiry queries
            entity.HasIndex(e => e.TemplateName);
            entity.HasIndex(e => e.Subject);
            entity.HasIndex(e => e.Status);

            entity.Property(e => e.SerialNumber).HasMaxLength(64).IsRequired();
            entity.Property(e => e.Subject).HasMaxLength(500).IsRequired();
            entity.Property(e => e.SubjectAlternativeNames).HasMaxLength(2000);
            entity.Property(e => e.TemplateName).HasMaxLength(200).IsRequired();
            entity.Property(e => e.Status).HasMaxLength(20).IsRequired();
            entity.Property(e => e.Requestor).HasMaxLength(256);
        });

        modelBuilder.Entity<AlertSent>(entity =>
        {
            entity.HasKey(e => e.Id);

            // Unique constraint: only one alert per certificate per threshold
            entity.HasIndex(e => new { e.CertificateId, e.ThresholdDays }).IsUnique();

            entity.Property(e => e.Channels).HasMaxLength(50).IsRequired();
            entity.Property(e => e.ErrorMessage).HasMaxLength(1000);

            entity.HasOne(e => e.Certificate)
                .WithMany()
                .HasForeignKey(e => e.CertificateId)
                .OnDelete(DeleteBehavior.Cascade);
        });
    }

    protected override void ConfigureConventions(ModelConfigurationBuilder configurationBuilder)
    {
        base.ConfigureConventions(configurationBuilder);

        // SQLite stores DateTime as TEXT with no zone, so values come back as
        // DateTimeKind.Unspecified and silently drop the UTC intent. Every DateTime in
        // this model is a UTC wall clock (stamped with DateTime.UtcNow, the ACME order
        // dates normalized to UTC at the controller, and the synced CA dates follow the
        // same UTC contract the expiry monitor relies on). Relabel materialized values
        // as UTC so .Kind matches how the code already treats them. The write side is
        // identity, so the stored format and existing rows are untouched.
        configurationBuilder
            .Properties<DateTime>()
            .HaveConversion<UtcDateTimeConverter>();
    }

    /// <summary>
    /// Restores DateTimeKind.Utc on every DateTime read back from SQLite. The stored
    /// value is written unchanged, so only the Kind is repaired on read.
    /// </summary>
    private sealed class UtcDateTimeConverter : ValueConverter<DateTime, DateTime>
    {
        public UtcDateTimeConverter()
            : base(v => v, v => DateTime.SpecifyKind(v, DateTimeKind.Utc))
        {
        }
    }
}

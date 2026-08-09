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

    // Domain policy audit: orders refused by the allowed domain list
    public DbSet<DomainPolicyRejection> DomainPolicyRejections => Set<DomainPolicyRejection>();

    // External account binding credentials (RFC 8555 §7.3.4)
    public DbSet<EabCredential> EabCredentials => Set<EabCredential>();

    // Device attestation (draft-ietf-acme-device-attest-08): per template
    // profiles, their device allowlists, and administrator managed trust anchors
    public DbSet<DeviceAttestationProfile> DeviceAttestationProfiles => Set<DeviceAttestationProfile>();
    public DbSet<DeviceAllowlistEntry> DeviceAllowlistEntries => Set<DeviceAllowlistEntry>();
    public DbSet<AttestationTrustAnchor> AttestationTrustAnchors => Set<AttestationTrustAnchor>();

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

            // Sorting and filtering only, like the certificate inventory's
            // NotBefore: CreatedAt backs both the default newest first order
            // and the Registered range, and Status backs the status filter
            // and its column sort.
            entity.HasIndex(e => e.CreatedAt);
            entity.HasIndex(e => e.Status);

            // Bound accounts keep their credential for attribution: revoke is
            // the credential's terminal state, never a hard delete, and
            // Restrict makes that structural.
            entity.HasIndex(e => e.ExternalAccountCredentialId);
            entity.HasOne(e => e.ExternalAccountCredential)
                .WithMany()
                .HasForeignKey(e => e.ExternalAccountCredentialId)
                .OnDelete(DeleteBehavior.Restrict);
        });

        modelBuilder.Entity<EabCredential>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.KeyId).IsUnique();
            entity.Property(e => e.KeyId).HasMaxLength(64).IsRequired();
            entity.Property(e => e.Name).HasMaxLength(200).IsRequired();
            entity.Property(e => e.SecretProtected).IsRequired();
            entity.Property(e => e.Status).HasMaxLength(20).IsRequired().HasDefaultValue("active");
            entity.Property(e => e.NamespacesJson).IsRequired().HasDefaultValue("[]");
            entity.Property(e => e.AdPrincipalSid).HasMaxLength(128);
            entity.Property(e => e.AdPrincipalName).HasMaxLength(256);
            entity.Property(e => e.AdPrincipalType).HasMaxLength(20);
        });

        modelBuilder.Entity<AcmeOrder>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.OrderId).IsUnique();
            entity.Property(e => e.OrderId).HasMaxLength(64).IsRequired();
            entity.Property(e => e.Status).HasMaxLength(20).IsRequired().HasDefaultValue("pending");
            entity.Property(e => e.TemplateId).HasMaxLength(200).IsRequired();
            entity.Property(e => e.IdentifiersJson).IsRequired();

            // Widens the index EF creates for the AccountId foreign key below
            // so the same one also covers CreatedAt. The account list reads
            // this table once per row for the order count and the last order
            // date, and once over the whole filtered set for the activity and
            // last order filters; those all seek on AccountId and then range
            // on CreatedAt. AccountId stays the leading column, so everything
            // the narrower index did, this still does.
            entity.HasIndex(e => new { e.AccountId, e.CreatedAt });

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
            // 32 fits "permanent-identifier" (20) and "hardware-module" (15);
            // the original 10 fit only "dns".
            entity.Property(e => e.IdentifierType).HasMaxLength(32).IsRequired();
            entity.Property(e => e.IdentifierValue).HasMaxLength(253).IsRequired();
            entity.Property(e => e.Status).HasMaxLength(20).IsRequired().HasDefaultValue("pending");
            entity.Property(e => e.AttestationFormat).HasMaxLength(32);

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

            // Sorting only, not filtering: the certificate list can order by the
            // CA requester (issue #156). It earns an index for the same reason
            // the columns above do, and for the reason the detail-only blocks
            // below do not.
            entity.HasIndex(e => e.Requestor);

            // Sorting only, like Requestor: NotBefore backs the Issued column,
            // and RequestDate backs the requestdate sort key, which the API
            // accepts on the wire even though no table column sends it yet.
            entity.HasIndex(e => e.NotBefore);
            entity.HasIndex(e => e.RequestDate);

            // Unlike the detail-only blocks below, this one earns an index: the
            // certificate detail page reads the relationship backwards, asking
            // which rows name this certificate as their replacement, and that is
            // a filter on this column (issue #154).
            entity.HasIndex(e => e.SupersededByCertificateId);

            entity.Property(e => e.SerialNumber).HasMaxLength(64).IsRequired();
            entity.Property(e => e.Subject).HasMaxLength(500).IsRequired();
            entity.Property(e => e.SubjectAlternativeNames).HasMaxLength(2000);
            entity.Property(e => e.TemplateName).HasMaxLength(200).IsRequired();
            entity.Property(e => e.Status).HasMaxLength(20).IsRequired();
            entity.Property(e => e.Requestor).HasMaxLength(256);

            // Cryptographic detail from the certificate's own DER. Deliberately
            // unindexed: an index only serves filtering and sorting, and these
            // fields are detail-endpoint only by design.
            entity.Property(e => e.KeyAlgorithm).HasMaxLength(40);
            entity.Property(e => e.SignatureAlgorithmOid).HasMaxLength(64);
            entity.Property(e => e.Sha256Thumbprint).HasMaxLength(64);
            entity.Property(e => e.ExtendedKeyUsageOids).HasMaxLength(1000);

            // The CA's disposition message. The CA schema allows 8192;
            // CertificateTextSanitizer truncates to this width on read, so the
            // column and the sanitizer agree. Unindexed for the same reason as
            // the block above.
            entity.Property(e => e.DispositionMessage).HasMaxLength(2000);
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

        modelBuilder.Entity<DomainPolicyRejection>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.OccurredAt); // Drives the activity feed ordering and the prune

            entity.Property(e => e.AccountId).HasMaxLength(64).IsRequired();
            entity.Property(e => e.TemplateId).HasMaxLength(200).IsRequired();
            entity.Property(e => e.RequestedIdentifiers).HasMaxLength(2000).IsRequired();
            entity.Property(e => e.RejectedIdentifiers).HasMaxLength(2000).IsRequired();
            entity.Property(e => e.ClientIp).HasMaxLength(64);
            entity.Property(e => e.Stage).HasMaxLength(20).IsRequired();
        });

        modelBuilder.Entity<DeviceAttestationProfile>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.TemplateId).IsUnique(); // one profile per template
            entity.Property(e => e.TemplateId).HasMaxLength(200).IsRequired();
            entity.Property(e => e.GateMode).HasMaxLength(20).IsRequired()
                .HasDefaultValue(DeviceAttestationGateModes.Allowlist);
            entity.Property(e => e.CsrIdentifierBinding).HasMaxLength(20).IsRequired()
                .HasDefaultValue(CsrIdentifierBindingModes.CnOrSan);
        });

        modelBuilder.Entity<DeviceAllowlistEntry>(entity =>
        {
            entity.HasKey(e => e.Id);
            // One row per device per profile. The lookup compares octet for
            // octet (SQLite BINARY collation), matching the draft's identifier
            // comparison rule.
            entity.HasIndex(e => new { e.ProfileId, e.IdentifierValue }).IsUnique();
            entity.Property(e => e.IdentifierValue).HasMaxLength(253).IsRequired();
            entity.Property(e => e.Note).HasMaxLength(500);

            entity.HasOne(e => e.Profile)
                .WithMany(p => p.AllowlistEntries)
                .HasForeignKey(e => e.ProfileId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<AttestationTrustAnchor>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.Sha256Fingerprint).IsUnique(); // dedupes re uploads
            entity.HasIndex(e => e.Format); // anchors are loaded per format
            entity.Property(e => e.Format).HasMaxLength(32).IsRequired();
            entity.Property(e => e.Name).HasMaxLength(200).IsRequired();
            entity.Property(e => e.CertificatePem).IsRequired();
            entity.Property(e => e.Sha256Fingerprint).HasMaxLength(64).IsRequired();
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

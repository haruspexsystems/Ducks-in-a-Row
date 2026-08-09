using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certus.Core.Acme.Services;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Certus.Core.Tests.Acme.Attestation;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Certus.Web.Tests;

/// <summary>
/// Factory for the device attestation integration tests. On top of the
/// shared test host it speeds the challenge validation worker's sweep up
/// (the device flow drives a real challenge through the background worker,
/// and the production 5 second interval would put dead seconds into every
/// test) and offers seeding helpers for the profile, allowlist, and trust
/// anchor tables, which have no admin API until the next phase.
/// </summary>
public class DeviceAttestWebApplicationFactory : CertusWebApplicationFactory
{
    /// <summary>The template every device test orders against.</summary>
    public const string Template = "WebServer";

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.ConfigureServices(services =>
        {
            // Replace the base factory's single shared in-memory connection
            // with a per factory file database. EF initializes its custom
            // SQLite functions on every DbContext construction, and doing
            // that on one connection the fast sweeping worker is querying at
            // the same time intermittently fails with "database is locked".
            // A file database gives every scope its own connection, and
            // SQLite's own locking (with the driver's default busy timeout)
            // handles worker versus request write races. The file lives in
            // the base factory's temp data directory, so its cleanup
            // disposes it.
            var descriptor = services.SingleOrDefault(
                d => d.ServiceType == typeof(DbContextOptions<CertusDbContext>));
            if (descriptor != null)
                services.Remove(descriptor);
            var databasePath = Path.Combine(TempDataDir, "device-tests.db");
            services.AddDbContext<CertusDbContext>(options =>
                options.UseSqlite($"Data Source={databasePath}"));

            services.PostConfigure<ChallengeValidationOptions>(
                o => o.PollIntervalSeconds = 0.2);
        });
    }

    /// <summary>
    /// Clears the device attestation tables and the policy audit trail so
    /// each test seeds exactly the state it asserts against.
    /// </summary>
    public async Task ResetDeviceStateAsync()
    {
        using var scope = Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        db.DeviceAllowlistEntries.RemoveRange(db.DeviceAllowlistEntries);
        db.DeviceAttestationProfiles.RemoveRange(db.DeviceAttestationProfiles);
        db.AttestationTrustAnchors.RemoveRange(db.AttestationTrustAnchors);
        db.DomainPolicyRejections.RemoveRange(db.DomainPolicyRejections);
        await db.SaveChangesAsync();
    }

    /// <summary>
    /// Seeds the device attestation profile for the test template. The
    /// default gate mode is allowlist, the entity default, so a test that
    /// wants the open observation mode has to say so.
    /// </summary>
    public async Task SeedProfileAsync(
        string gateMode = DeviceAttestationGateModes.Allowlist,
        string csrIdentifierBinding = CsrIdentifierBindingModes.CnOrSan,
        bool enabled = true,
        params string[] allowlistedDevices)
    {
        using var scope = Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        var profile = new DeviceAttestationProfile
        {
            TemplateId = Template,
            Enabled = enabled,
            GateMode = gateMode,
            CsrIdentifierBinding = csrIdentifierBinding
        };
        foreach (var device in allowlistedDevices)
            profile.AllowlistEntries.Add(new DeviceAllowlistEntry { IdentifierValue = device });
        db.DeviceAttestationProfiles.Add(profile);
        await db.SaveChangesAsync();
    }

    /// <summary>
    /// Seeds a custom apple format trust anchor, the way tests introduce
    /// the synthetic root (the embedded Apple root refuses synthetic
    /// chains, which is its job).
    /// </summary>
    public async Task SeedAnchorAsync(X509Certificate2 root)
    {
        using var scope = Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        db.AttestationTrustAnchors.Add(new AttestationTrustAnchor
        {
            Format = "apple",
            Name = "synthetic test root",
            CertificatePem = SyntheticAttestationBuilder.ToPem(root),
            Sha256Fingerprint = Convert.ToHexString(SHA256.HashData(root.RawData)).ToLowerInvariant(),
            Enabled = true
        });
        await db.SaveChangesAsync();
    }

    /// <summary>Removes one device from the allowlist, simulating a delisting mid flight.</summary>
    public async Task RemoveAllowlistEntryAsync(string identifierValue)
    {
        using var scope = Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        var entries = await db.DeviceAllowlistEntries
            .Where(e => e.IdentifierValue == identifierValue)
            .ToListAsync();
        db.DeviceAllowlistEntries.RemoveRange(entries);
        await db.SaveChangesAsync();
    }

    /// <summary>The policy audit rows recorded under one stage.</summary>
    public async Task<List<DomainPolicyRejection>> GetAuditRowsAsync(string stage)
    {
        using var scope = Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        return await db.DomainPolicyRejections
            .AsNoTracking()
            .Where(r => r.Stage == stage)
            .ToListAsync();
    }
}

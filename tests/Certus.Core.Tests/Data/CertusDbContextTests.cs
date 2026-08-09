using Certus.Core.Adcs;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace Certus.Core.Tests.Data;

/// <summary>
/// Verifies the CertusDbContext can be created and migrated with SQLite.
/// </summary>
public class CertusDbContextTests : IDisposable
{
    private readonly CertusDbContext _context;

    public CertusDbContextTests()
    {
        var options = new DbContextOptionsBuilder<CertusDbContext>()
            .UseSqlite("Data Source=:memory:")
            .Options;

        _context = new CertusDbContext(options);
        _context.Database.OpenConnection();
        _context.Database.EnsureCreated();
    }

    [Fact]
    public void DbContext_CanBeCreated()
    {
        _context.Should().NotBeNull();
    }

    [Fact]
    public void DbContext_DatabaseIsCreated()
    {
        var canConnect = _context.Database.CanConnect();
        canConnect.Should().BeTrue();
    }

    [Fact]
    public void DbContext_ProviderIsSqlite()
    {
        var providerName = _context.Database.ProviderName;
        providerName.Should().Contain("Sqlite");
    }

    [Fact]
    public void DateTime_RoundTripsAsUtc()
    {
        // Store a UTC stamp, then force a real read back from SQLite (clearing the
        // change tracker) so the value converter runs. Without the converter the Kind
        // comes back Unspecified; with it the UTC intent is preserved.
        var account = new AcmeAccount
        {
            AccountId = "acct-utc-roundtrip",
            JwkThumbprint = "thumb-utc-roundtrip",
            JwkJson = "{}",
            CreatedAt = DateTime.UtcNow
        };
        _context.AcmeAccounts.Add(account);
        _context.SaveChanges();
        _context.ChangeTracker.Clear();

        var loaded = _context.AcmeAccounts.Single(a => a.AccountId == "acct-utc-roundtrip");

        loaded.CreatedAt.Kind.Should().Be(DateTimeKind.Utc);
        loaded.CreatedAt.Should().BeCloseTo(account.CreatedAt, TimeSpan.FromSeconds(1));
    }

    [Fact]
    public void AcmeChallenge_IsIndexedOnStatus()
    {
        var indexes = _context.Model
            .FindEntityType(typeof(AcmeChallenge))!
            .GetIndexes();

        indexes.Should().Contain(
            i => i.Properties.Count == 1 && i.Properties[0].Name == nameof(AcmeChallenge.Status),
            "the background validation sweep filters challenges by Status");
    }

    [Fact]
    public void AcmeAuthorization_IdentifierTypeFitsDeviceTypes()
    {
        var maxLength = _context.Model
            .FindEntityType(typeof(AcmeAuthorization))!
            .FindProperty(nameof(AcmeAuthorization.IdentifierType))!
            .GetMaxLength();

        maxLength.Should().Be(32,
            "\"permanent-identifier\" is 20 characters and the old cap of 10 fit only \"dns\"");
    }

    [Fact]
    public void SyncedCertificate_DispositionMessageMatchesTheSanitizerCap()
    {
        var maxLength = _context.Model
            .FindEntityType(typeof(SyncedCertificate))!
            .FindProperty(nameof(SyncedCertificate.DispositionMessage))!
            .GetMaxLength();

        maxLength.Should().Be(CertificateTextSanitizer.MaxDispositionMessageLength,
            "the sanitizer truncates the CA's message to this width on read, so the "
            + "column and the sanitizer have to agree; the CA schema allows 8192");
    }

    [Fact]
    public void SyncedCertificate_SubjectMatchesTheSanitizerCap()
    {
        var maxLength = _context.Model
            .FindEntityType(typeof(SyncedCertificate))!
            .FindProperty(nameof(SyncedCertificate.Subject))!
            .GetMaxLength();

        maxLength.Should().Be(CertificateTextSanitizer.MaxSubjectLength,
            "the sanitizer truncates every subject source to this width on read, so the "
            + "column and the sanitizer have to agree; SQLite does not enforce the declared "
            + "width itself, and the column is indexed (issue #224)");
    }

    [Fact]
    public void DeviceAttestation_ColumnsAndTables_RoundTrip()
    {
        var profile = new DeviceAttestationProfile
        {
            TemplateId = "DeviceAuth",
            GateMode = DeviceAttestationGateModes.Open,
            CsrIdentifierBinding = CsrIdentifierBindingModes.SanRequired
        };
        profile.AllowlistEntries.Add(new DeviceAllowlistEntry
        {
            IdentifierValue = "SN-1",
            Note = "lab iPad"
        });
        _context.DeviceAttestationProfiles.Add(profile);

        _context.AttestationTrustAnchors.Add(new AttestationTrustAnchor
        {
            Format = "apple",
            Name = "Test root",
            CertificatePem = "-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----",
            Sha256Fingerprint = new string('a', 64)
        });

        var authz = new AcmeAuthorization
        {
            AuthorizationId = "authz-device",
            Order = new AcmeOrder
            {
                OrderId = "order-device",
                TemplateId = "DeviceAuth",
                ExpiresAt = DateTime.UtcNow.AddDays(1),
                Account = new AcmeAccount
                {
                    AccountId = "acct-device",
                    JwkThumbprint = "thumb-device",
                    JwkJson = "{}"
                }
            },
            IdentifierType = "permanent-identifier",
            IdentifierValue = "SN-1",
            ExpiresAt = DateTime.UtcNow.AddDays(1),
            AttestedSpki = "c3BraQ==",
            AttestationFormat = "apple",
            AttestedPropertiesJson = """{"serial":"SN-1"}"""
        };
        authz.Challenges.Add(new AcmeChallenge
        {
            ChallengeId = "chal-device",
            Type = "device-attest-01",
            Token = "tok-device",
            AttestationObject = "b2Jq"
        });
        _context.AcmeAuthorizations.Add(authz);

        _context.SaveChanges();
        _context.ChangeTracker.Clear();

        var loadedProfile = _context.DeviceAttestationProfiles
            .Include(p => p.AllowlistEntries)
            .Single(p => p.TemplateId == "DeviceAuth");
        loadedProfile.GateMode.Should().Be(DeviceAttestationGateModes.Open);
        loadedProfile.CsrIdentifierBinding.Should().Be(CsrIdentifierBindingModes.SanRequired);
        loadedProfile.AllowlistEntries.Should().ContainSingle(
            e => e.IdentifierValue == "SN-1" && e.Note == "lab iPad");

        var loadedAuthz = _context.AcmeAuthorizations
            .Include(a => a.Challenges)
            .Single(a => a.AuthorizationId == "authz-device");
        loadedAuthz.IdentifierType.Should().Be("permanent-identifier");
        loadedAuthz.AttestedSpki.Should().Be("c3BraQ==");
        loadedAuthz.AttestationFormat.Should().Be("apple");
        loadedAuthz.AttestedPropertiesJson.Should().Contain("SN-1");
        loadedAuthz.Challenges.Single().AttestationObject.Should().Be("b2Jq");

        _context.AttestationTrustAnchors
            .Single(a => a.Format == "apple")
            .Sha256Fingerprint.Should().Be(new string('a', 64));
    }

    [Fact]
    public void DeviceAllowlist_DuplicateEntryInProfile_IsRejected()
    {
        var profile = new DeviceAttestationProfile { TemplateId = "DupTest" };
        profile.AllowlistEntries.Add(new DeviceAllowlistEntry { IdentifierValue = "SN-DUP" });
        _context.DeviceAttestationProfiles.Add(profile);
        _context.SaveChanges();

        profile.AllowlistEntries.Add(new DeviceAllowlistEntry { IdentifierValue = "SN-DUP" });
        var act = () => _context.SaveChanges();

        act.Should().Throw<DbUpdateException>(
            "one profile listing the same device twice is a data error the schema must refuse");
    }

    public void Dispose()
    {
        _context.Database.CloseConnection();
        _context.Dispose();
    }
}

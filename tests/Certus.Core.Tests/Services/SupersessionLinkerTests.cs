using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Certus.Core.Services;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace Certus.Core.Tests.Services;

/// <summary>
/// The supersession inference (issue #154). Two halves: the matching key, which
/// is pure, and the relink pass, which walks each lineage and decides who
/// replaced whom.
/// </summary>
public class SupersessionLinkerTests : IDisposable
{
    private const string Issued = "Issued";
    private const string Revoked = "Revoked";

    private readonly SqliteConnection _connection;
    private readonly CertusDbContext _db;
    private int _nextRequestId;

    public SupersessionLinkerTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();

        var options = new DbContextOptionsBuilder<CertusDbContext>()
            .UseSqlite(_connection)
            .Options;
        _db = new CertusDbContext(options);
        _db.Database.EnsureCreated();
    }

    // ---- The matching key ------------------------------------------------

    [Fact]
    public void KeyFor_SanOrderAndCase_DoNotMatter()
    {
        // The acceptance criterion's own example, verbatim.
        var a = SupersessionLinker.KeyFor("WebServer", "", "dns:A.example.com, dns:b.example.com");
        var b = SupersessionLinker.KeyFor("WebServer", "", "dns:b.example.com, dns:a.example.com");

        a.Should().NotBeNull();
        a.Should().Be(b);
    }

    [Fact]
    public void KeyFor_DuplicateSans_Collapse()
    {
        var withDuplicate = SupersessionLinker.KeyFor(
            "WebServer", "", "dns:a.example.com, dns:A.EXAMPLE.COM, dns:b.example.com");
        var without = SupersessionLinker.KeyFor(
            "WebServer", "", "dns:a.example.com, dns:b.example.com");

        withDuplicate.Should().Be(without);
    }

    [Fact]
    public void KeyFor_StripsDnsAndIpLabelsButKeepsIpv6Colons()
    {
        var labelled = SupersessionLinker.KeyFor("WebServer", "", "dns:a.example.com, ip:2001:db8::1");
        var bare = SupersessionLinker.KeyFor("WebServer", "", "a.example.com, 2001:db8::1");

        labelled.Should().Be(bare);
        // Splitting on the colon rather than testing the prefix would have eaten
        // the address; the same trap AdcsClient.FirstSanDisplayName documents.
        labelled.Should().Contain("2001:db8::1");
    }

    [Fact]
    public void KeyFor_SanOnlyCertificateWithEmptySubject_IsKeyedOnItsSans()
    {
        // The normal ACME shape: no subject DN at all.
        var key = SupersessionLinker.KeyFor("WebServer", "", "dns:acme.example.com");

        key.Should().NotBeNull();
        key.Should().Contain("acme.example.com");
    }

    [Fact]
    public void KeyFor_NoSans_FallsBackToSubjectCommonName()
    {
        var fromDn = SupersessionLinker.KeyFor("WebServer", "CN=host.example.com, OU=IT, O=Example", null);
        var fromCnOnly = SupersessionLinker.KeyFor("WebServer", "CN=host.example.com", null);

        fromDn.Should().NotBeNull();
        // Only the CN takes part, so a changed OU does not split a lineage.
        fromDn.Should().Be(fromCnOnly);
    }

    [Fact]
    public void KeyFor_NoSansAndBareNameSubject_MatchesTheDnForm()
    {
        // CertificateSyncService backfills a bare name, not a DN, when the CA
        // returned no subject. The two spellings have to key identically.
        var bare = SupersessionLinker.KeyFor("WebServer", "host.example.com", null);
        var dn = SupersessionLinker.KeyFor("WebServer", "CN=host.example.com", null);

        bare.Should().Be(dn);
    }

    [Fact]
    public void KeyFor_CommonNamesDifferingAfterAQuotedComma_DoNotShareALineage()
    {
        // The sharper half of issue #231, and the reason the fix is not only a
        // display correction. Reading to the first comma cut both of these down
        // to the same fragment, so two unrelated certificates keyed into one
        // lineage and the dashboard told an operator that one had replaced the
        // other.
        var first = SupersessionLinker.KeyFor(
            "WebServer", "CN=\"host.example.com, O=Team A\", O=Example", null);
        var second = SupersessionLinker.KeyFor(
            "WebServer", "CN=\"host.example.com, O=Team B\", O=Example", null);

        first.Should().NotBeNull();
        first.Should().NotBe(second);
    }

    [Fact]
    public void KeyFor_QuotedCommonNameDoesNotCollideWithItsOwnFragment()
    {
        // The other direction of the same defect. A certificate genuinely named
        // "host.example.com" must not share a lineage with one whose name merely
        // starts that way before an escaped comma.
        var quoted = SupersessionLinker.KeyFor(
            "WebServer", "CN=\"host.example.com, O=Impostor\", O=Example", null);
        var plain = SupersessionLinker.KeyFor(
            "WebServer", "CN=host.example.com, O=Example", null);

        quoted.Should().NotBe(plain);
    }

    [Fact]
    public void KeyFor_ANameEndingInABackslashDoesNotShareALineageWithAQuotedName()
    {
        // The inverse of what this test asserted before issue #296, and the third
        // instance of the collision the two tests above describe.
        //
        // It used to read these as two spellings of one name, on the premise that
        // either encoder might have rendered the row. Only one does: PR #293 moved
        // MockAdcsClient onto X509Certificate2, so every subject that reaches the
        // reader is the Windows form, and in that form a backslash is a literal
        // character of the name. So the first string names a certificate whose
        // common name is "host.example.com, O=Team", and the second names an
        // unrelated one whose common name is "host.example.com\" that happens to
        // sit in an organisation called Team.
        //
        // Keying them together was not a harmless generosity. The lineage is what
        // the dashboard uses to say one certificate replaced another, so a shared
        // key between two unrelated certificates is a false supersession claim,
        // and a requester on a template with enrollee supplies subject picks the
        // name that produces it.
        var quoted = SupersessionLinker.KeyFor(
            "WebServer", "CN=\"host.example.com, O=Team\", O=Example", null);
        var trailingBackslash = SupersessionLinker.KeyFor(
            "WebServer", "CN=host.example.com\\, O=Team, O=Example", null);

        quoted.Should().NotBeNull();
        trailingBackslash.Should().NotBeNull();
        quoted.Should().NotBe(trailingBackslash);
    }

    [Fact]
    public void KeyFor_ANameEndingInABackslashKeysOnTheNameItActuallyCarries()
    {
        // The positive half: the same certificate keys the same way however much
        // of the subject follows it, which is what makes a renewal of a name
        // ending in a backslash link to its predecessor at all. Before issue #296
        // the key absorbed whatever components came after the common name, so two
        // renewals of one name into different organisational units keyed apart
        // and neither superseded the other.
        var withOrg = SupersessionLinker.KeyFor(
            "WebServer", "CN=CORP\\, OU=Sales, O=Example", null);
        var withDifferentOrg = SupersessionLinker.KeyFor(
            "WebServer", "CN=CORP\\, OU=Support, O=Example", null);

        withOrg.Should().Be(withDifferentOrg);
    }

    [Fact]
    public void KeyFor_SubjectCommonNameIsCaseInsensitive()
    {
        var upper = SupersessionLinker.KeyFor("WebServer", "CN=HOST.example.com", null);
        var lower = SupersessionLinker.KeyFor("WebServer", "CN=host.example.com", null);

        upper.Should().Be(lower);
    }

    [Fact]
    public void KeyFor_DifferentTemplates_ProduceDifferentKeys()
    {
        var web = SupersessionLinker.KeyFor("WebServer", "", "dns:a.example.com");
        var internalServer = SupersessionLinker.KeyFor("InternalServer", "", "dns:a.example.com");

        web.Should().NotBe(internalServer);
    }

    [Theory]
    [InlineData(null, "CN=host.example.com", "dns:a.example.com")] // no template
    [InlineData("", "CN=host.example.com", "dns:a.example.com")]
    [InlineData("   ", "CN=host.example.com", "dns:a.example.com")]
    [InlineData("WebServer", "", null)]                            // nothing to name it by
    [InlineData("WebServer", "   ", "")]
    [InlineData("WebServer", null, " , , ")]                       // separators only
    public void KeyFor_NothingToKeyOn_ReturnsNull(string? template, string? subject, string? sans)
    {
        // Load bearing. A shared empty key would herd every nameless row into one
        // false lineage claiming to replace each other.
        SupersessionLinker.KeyFor(template, subject, sans).Should().BeNull();
    }

    // ---- The relink pass -------------------------------------------------

    [Fact]
    public async Task Relink_ChainsALineageOldestToNewest()
    {
        var a = Add("WebServer", 2024, sans: "dns:app.example.com");
        var b = Add("WebServer", 2025, sans: "dns:app.example.com");
        var c = Add("WebServer", 2026, sans: "dns:app.example.com");

        await RelinkAsync();

        a.SupersededByCertificateId.Should().Be(b.Id);
        b.SupersededByCertificateId.Should().Be(c.Id);
        // The newest in a lineage is never marked superseded.
        c.SupersededByCertificateId.Should().BeNull();
    }

    [Fact]
    public async Task Relink_MatchesAcrossSanOrderAndCase()
    {
        var older = Add("WebServer", 2024, sans: "dns:A.example.com, dns:b.example.com");
        var newer = Add("WebServer", 2025, sans: "dns:b.example.com, dns:a.example.com");

        await RelinkAsync();

        older.SupersededByCertificateId.Should().Be(newer.Id);
    }

    [Fact]
    public async Task Relink_SameNamesDifferentTemplates_AreNotLinked()
    {
        var web = Add("WebServer", 2024, sans: "dns:app.example.com");
        var internalServer = Add("InternalServer", 2025, sans: "dns:app.example.com");

        await RelinkAsync();

        web.SupersededByCertificateId.Should().BeNull();
        internalServer.SupersededByCertificateId.Should().BeNull();
    }

    [Fact]
    public async Task Relink_RevokedCertificate_DoesNotSupersedeAnything()
    {
        var a = Add("WebServer", 2024, sans: "dns:app.example.com");
        var b = Add("WebServer", 2025, sans: "dns:app.example.com", status: Revoked);
        var c = Add("WebServer", 2026, sans: "dns:app.example.com");

        await RelinkAsync();

        // A skips the revoked B: naming B the replacement would say the name is
        // covered when nothing is actually serving it.
        a.SupersededByCertificateId.Should().Be(c.Id);
        // A revoked certificate can still be superseded itself.
        b.SupersededByCertificateId.Should().Be(c.Id);
        c.SupersededByCertificateId.Should().BeNull();
    }

    [Fact]
    public async Task Relink_NewestIsRevoked_LeavesTheLineageUnlinked()
    {
        var a = Add("WebServer", 2024, sans: "dns:app.example.com");
        var b = Add("WebServer", 2025, sans: "dns:app.example.com", status: Revoked);

        await RelinkAsync();

        a.SupersededByCertificateId.Should().BeNull();
        b.SupersededByCertificateId.Should().BeNull();
    }

    [Fact]
    public async Task Relink_NoSans_LinksOnSubjectCommonName()
    {
        var older = Add("WebServer", 2024, subject: "CN=host.example.com, OU=IT");
        var newer = Add("WebServer", 2025, subject: "CN=host.example.com, OU=Platform");

        await RelinkAsync();

        older.SupersededByCertificateId.Should().Be(newer.Id);
    }

    [Fact]
    public async Task Relink_NamelessRows_DoNotFormALineage()
    {
        // Same template, no SANs, no subject. Without the null key guard these
        // would all claim to replace one another.
        var first = Add("WebServer", 2024);
        var second = Add("WebServer", 2025);
        var third = Add("WebServer", 2026);

        await RelinkAsync();

        first.SupersededByCertificateId.Should().BeNull();
        second.SupersededByCertificateId.Should().BeNull();
        third.SupersededByCertificateId.Should().BeNull();
    }

    [Theory]
    [InlineData("Pending")]
    [InlineData("Denied")]
    [InlineData("Failed")]
    public async Task Relink_RequestRowsThatNeverBecameCertificates_TakeNoPart(string status)
    {
        var certificate = Add("WebServer", 2024, sans: "dns:app.example.com");
        var request = Add("WebServer", 2026, sans: "dns:app.example.com", status: status);

        await RelinkAsync();

        // The request row carries placeholder dates and no real names, so it can
        // neither supersede nor be superseded.
        certificate.SupersededByCertificateId.Should().BeNull();
        request.SupersededByCertificateId.Should().BeNull();
    }

    [Fact]
    public async Task Relink_ClearsALinkThatNoLongerHolds()
    {
        var a = Add("WebServer", 2024, sans: "dns:app.example.com");
        var b = Add("WebServer", 2025, sans: "dns:app.example.com");
        await RelinkAsync();
        a.SupersededByCertificateId.Should().Be(b.Id);

        // The CA reports B revoked on a later cycle, so it stops qualifying.
        b.Status = Revoked;
        await _db.SaveChangesAsync();

        await RelinkAsync();

        a.SupersededByCertificateId.Should().BeNull();
    }

    [Fact]
    public async Task Relink_IsIdempotent()
    {
        Add("WebServer", 2024, sans: "dns:app.example.com");
        Add("WebServer", 2025, sans: "dns:app.example.com");

        var firstRun = await RelinkAsync();
        var secondRun = await RelinkAsync();

        firstRun.Should().Be(1);
        // Nothing moved, so nothing is written. This is what keeps the pass cheap
        // on a steady inventory.
        secondRun.Should().Be(0);
    }

    [Fact]
    public async Task Relink_IdenticalNotBefore_BreaksTheTieOnId()
    {
        var sameInstant = new DateTime(2025, 6, 1, 12, 0, 0, DateTimeKind.Utc);
        var first = Add("WebServer", sameInstant, sans: "dns:app.example.com");
        var second = Add("WebServer", sameInstant, sans: "dns:app.example.com");

        await RelinkAsync();

        // Deterministic rather than arbitrary: the lower Id is treated as earlier.
        first.SupersededByCertificateId.Should().Be(second.Id);
        second.SupersededByCertificateId.Should().BeNull();
    }

    [Fact]
    public async Task Relink_KeepsSeparateLineagesApart()
    {
        var appOld = Add("WebServer", 2024, sans: "dns:app.example.com");
        var appNew = Add("WebServer", 2025, sans: "dns:app.example.com");
        var apiOld = Add("WebServer", 2024, sans: "dns:api.example.com");
        var apiNew = Add("WebServer", 2026, sans: "dns:api.example.com");

        await RelinkAsync();

        appOld.SupersededByCertificateId.Should().Be(appNew.Id);
        apiOld.SupersededByCertificateId.Should().Be(apiNew.Id);
        appNew.SupersededByCertificateId.Should().BeNull();
        apiNew.SupersededByCertificateId.Should().BeNull();
    }

    [Fact]
    public async Task Relink_PartialSanOverlap_IsNotAMatch()
    {
        // The rule is the whole name set, not any shared name: a certificate that
        // dropped a name is a different coverage, not a renewal.
        var twoNames = Add("WebServer", 2024, sans: "dns:app.example.com, dns:www.example.com");
        var oneName = Add("WebServer", 2025, sans: "dns:app.example.com");

        await RelinkAsync();

        twoNames.SupersededByCertificateId.Should().BeNull();
        oneName.SupersededByCertificateId.Should().BeNull();
    }

    // ---- Helpers ---------------------------------------------------------

    private SyncedCertificate Add(
        string template,
        int notBeforeYear,
        string? sans = null,
        string subject = "",
        string status = Issued)
        => Add(template, new DateTime(notBeforeYear, 1, 1, 0, 0, 0, DateTimeKind.Utc), sans, subject, status);

    private SyncedCertificate Add(
        string template,
        DateTime notBefore,
        string? sans = null,
        string subject = "",
        string status = Issued)
    {
        _nextRequestId++;
        var entity = new SyncedCertificate
        {
            RequestId = _nextRequestId,
            SerialNumber = _nextRequestId.ToString("X8"),
            Subject = subject,
            SubjectAlternativeNames = sans,
            TemplateName = template,
            NotBefore = notBefore,
            NotAfter = notBefore.AddYears(1),
            Status = status,
            RequestDate = notBefore.AddDays(-1)
        };
        _db.SyncedCertificates.Add(entity);
        _db.SaveChanges();
        return entity;
    }

    /// <summary>Runs the pass and saves, the way the sync service does.</summary>
    private async Task<int> RelinkAsync()
    {
        var changed = await SupersessionLinker.RelinkAsync(_db, CancellationToken.None);
        if (changed > 0)
            await _db.SaveChangesAsync();
        return changed;
    }

    public void Dispose()
    {
        _db.Dispose();
        _connection.Dispose();
        GC.SuppressFinalize(this);
    }
}

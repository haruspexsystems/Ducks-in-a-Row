using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certus.Core.Adcs;
using Certus.Core.Configuration;
using Certus.Core.Setup;
using Certus.Core.Tests.Adcs;

namespace Certus.Core.Tests.Setup;

/// <summary>
/// Following a pinned HTTPS certificate across a renewal (issue #471). The service
/// pins by thumbprint and a renewal issues a new thumbprint, so without this the
/// next boot after a renewal served the self signed certificate.
/// </summary>
public class HttpsCertificateFollowTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 10, 11, 12, 0, 0, TimeSpan.Zero);
    private const string Subject = "CN=web01.corp.example.com";
    private static readonly CertificateTemplateIdentity WebServer =
        new("1.3.6.1.4.1.311.21.8.1.2.3", 100, 2, null);

    private readonly string _tempDir =
        Path.Combine(Path.GetTempPath(), $"certus-follow-{Guid.NewGuid():N}");

    public HttpsCertificateFollowTests() => Directory.CreateDirectory(_tempDir);

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, recursive: true);
    }

    private static HttpsCertificateFacts Facts(
        string thumbprint,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null,
        bool archived = false,
        bool hasKey = true,
        string subject = Subject,
        CertificateTemplateIdentity? template = null,
        bool serverAuth = true,
        bool ca = false,
        bool noTemplate = false) =>
        new(thumbprint, subject, noTemplate ? null : template ?? WebServer,
            notBefore ?? Now.AddDays(-300), notAfter ?? Now.AddDays(65),
            hasKey, archived, serverAuth, ca);

    // The shape autoenrolment leaves behind: the old certificate archived, the
    // renewal issued later to the same subject from the same template.
    private static HttpsCertificateFacts Old(bool archived = true, DateTimeOffset? notAfter = null) =>
        Facts("AAAA", notBefore: Now.AddDays(-300), notAfter: notAfter ?? Now.AddDays(65), archived: archived);

    private static HttpsCertificateFacts Renewal(
        string thumbprint = "BBBB",
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null,
        bool archived = false,
        bool hasKey = true,
        string subject = Subject,
        CertificateTemplateIdentity? template = null,
        bool serverAuth = true,
        bool ca = false) =>
        Facts(thumbprint, notBefore ?? Now.AddDays(-5), notAfter ?? Now.AddDays(360),
            archived, hasKey, subject, template, serverAuth, ca);

    [Fact]
    public void A_current_pinned_certificate_is_served()
    {
        var choice = HttpsCertificateFollow.Choose("AAAA", [Old(archived: false), Renewal()], Now);

        choice.Outcome.Should().Be(HttpsCertificateChoiceOutcome.Pinned);
        choice.ServeThumbprint.Should().Be("AAAA");
    }

    [Fact]
    public void An_archived_pinned_certificate_is_followed_to_its_renewal()
    {
        var choice = HttpsCertificateFollow.Choose("AAAA", [Old(), Renewal()], Now);

        choice.Outcome.Should().Be(HttpsCertificateChoiceOutcome.Followed);
        choice.ServeThumbprint.Should().Be("BBBB");
        choice.PinnedThumbprint.Should().Be("AAAA");
    }

    [Fact]
    public void An_expired_pinned_certificate_is_followed_to_its_renewal()
    {
        var choice = HttpsCertificateFollow.Choose(
            "AAAA", [Old(archived: false, notAfter: Now.AddDays(-1)), Renewal()], Now);

        choice.Outcome.Should().Be(HttpsCertificateChoiceOutcome.Followed);
        choice.ServeThumbprint.Should().Be("BBBB");
    }

    [Fact]
    public void A_thumbprint_missing_from_the_store_has_nothing_to_follow_from()
    {
        var choice = HttpsCertificateFollow.Choose("CCCC", [Old(), Renewal()], Now);

        choice.Outcome.Should().Be(HttpsCertificateChoiceOutcome.NotInStore);
        choice.ServeThumbprint.Should().BeNull();
    }

    [Fact]
    public void A_renewal_from_a_different_template_is_not_followed()
    {
        var other = WebServer with { Oid = "1.3.6.1.4.1.311.21.8.9.9.9" };

        var choice = HttpsCertificateFollow.Choose(
            "AAAA", [Old(notAfter: Now.AddDays(-1)), Renewal(template: other)], Now);

        choice.Outcome.Should().Be(HttpsCertificateChoiceOutcome.ExpiredNoSuccessor);
        choice.ServeThumbprint.Should().BeNull();
    }

    [Fact]
    public void A_renewal_after_a_template_version_bump_is_still_followed()
    {
        var reenrolled = WebServer with { MajorVersion = 101, MinorVersion = 0 };

        HttpsCertificateFollow.Choose("AAAA", [Old(), Renewal(template: reenrolled)], Now)
            .ServeThumbprint.Should().Be("BBBB");
    }

    [Fact]
    public void A_certificate_for_another_subject_is_not_followed()
    {
        HttpsCertificateFollow.Choose(
                "AAAA", [Old(), Renewal(subject: "CN=web02.corp.example.com")], Now)
            .Outcome.Should().Be(HttpsCertificateChoiceOutcome.ArchivedNoSuccessor);
    }

    [Fact]
    public void The_subject_compares_without_regard_to_case()
    {
        HttpsCertificateFollow.Choose(
                "AAAA", [Old(), Renewal(subject: "CN=WEB01.corp.example.com")], Now)
            .ServeThumbprint.Should().Be("BBBB");
    }

    public static TheoryData<string, HttpsCertificateFacts> UnusableSuccessors => new()
    {
        { "no private key", Renewal(hasKey: false) },
        { "itself archived", Renewal(archived: true) },
        { "expired", Renewal(notBefore: Now.AddDays(-30), notAfter: Now.AddDays(-1)) },
        { "not yet valid", Renewal(notBefore: Now.AddDays(1)) },
        { "client authentication only", Renewal(serverAuth: false) },
        { "a CA certificate", Renewal(ca: true) },
        { "issued before the pinned one", Renewal(notBefore: Now.AddDays(-400)) },
        { "holding a key this process cannot sign with", Renewal() with { KeyUsable = false } },
    };

    [Theory]
    [MemberData(nameof(UnusableSuccessors))]
    public void A_successor_that_cannot_serve_is_skipped(string why, HttpsCertificateFacts candidate)
    {
        var choice = HttpsCertificateFollow.Choose(
            "AAAA", [Old(notAfter: Now.AddDays(-1)), candidate], Now);

        choice.ServeThumbprint.Should().BeNull(because: $"a successor that is {why} cannot be served");
        choice.Outcome.Should().Be(HttpsCertificateChoiceOutcome.ExpiredNoSuccessor);
    }

    [Fact]
    public void A_pinned_certificate_naming_no_template_cannot_be_followed()
    {
        var pinned = Facts("AAAA", notAfter: Now.AddDays(-1), noTemplate: true);

        var choice = HttpsCertificateFollow.Choose("AAAA", [pinned, Renewal()], Now);

        choice.Outcome.Should().Be(HttpsCertificateChoiceOutcome.NoIdentityToFollow);
        choice.ServeThumbprint.Should().BeNull();
    }

    [Fact]
    public void A_version_1_template_name_is_followed_without_regard_to_case()
    {
        var v1 = new CertificateTemplateIdentity(null, null, null, "WebServer");
        var pinned = Facts("AAAA", notAfter: Now.AddDays(-1), template: v1);
        var renewal = Renewal(template: v1 with { Name = "webserver" });

        HttpsCertificateFollow.Choose("AAAA", [pinned, renewal], Now)
            .ServeThumbprint.Should().Be("BBBB");
    }

    [Fact]
    public void An_archived_certificate_that_is_still_valid_is_served_when_nothing_replaced_it()
    {
        // Before issue #471 the store was opened without archived certificates, so
        // this certificate read as missing and the service fell back to self signed.
        var choice = HttpsCertificateFollow.Choose("AAAA", [Old()], Now);

        choice.Outcome.Should().Be(HttpsCertificateChoiceOutcome.ArchivedNoSuccessor);
        choice.ServeThumbprint.Should().Be("AAAA");
    }

    [Fact]
    public void A_current_pinned_certificate_without_its_key_falls_back()
    {
        var pinned = Facts("AAAA", hasKey: false);

        HttpsCertificateFollow.Choose("AAAA", [pinned], Now)
            .Outcome.Should().Be(HttpsCertificateChoiceOutcome.NoPrivateKey);
    }

    [Fact]
    public void The_newest_successor_wins_and_ties_resolve_the_same_way_every_boot()
    {
        var older = Renewal("CCCC", notBefore: Now.AddDays(-20));
        var newest = Renewal("DDDD", notBefore: Now.AddDays(-2), notAfter: Now.AddDays(300));
        var sameStartLongerLife = Renewal("EEEE", notBefore: Now.AddDays(-2), notAfter: Now.AddDays(350));
        var twinA = Renewal("FFF1", notBefore: Now.AddDays(-1), notAfter: Now.AddDays(400));
        var twinB = Renewal("FFF0", notBefore: Now.AddDays(-1), notAfter: Now.AddDays(400));

        HttpsCertificateFollow.Choose("AAAA", [Old(), older, newest, sameStartLongerLife], Now)
            .ServeThumbprint.Should().Be("EEEE");
        HttpsCertificateFollow.Choose("AAAA", [Old(), twinA, twinB], Now)
            .ServeThumbprint.Should().Be("FFF0");
    }

    [Fact]
    public void An_empty_subject_matches_on_the_subject_alternative_names()
    {
        var pinned = Facts("AAAA", subject: "san:web01.corp.example.com", archived: true);
        var renewal = Renewal(subject: "san:web01.corp.example.com");

        HttpsCertificateFollow.Choose("AAAA", [pinned, renewal], Now)
            .ServeThumbprint.Should().Be("BBBB");
    }

    [Fact]
    public void A_thumbprint_copied_from_the_certificates_console_still_matches()
    {
        // The console puts a left to right mark in front and spaces between bytes.
        HttpsCertificateFollow.Choose("‎aa aa", [Old(archived: false)], Now)
            .Outcome.Should().Be(HttpsCertificateChoiceOutcome.Pinned);
    }

    [Fact]
    public void Describe_reads_the_facts_off_a_real_certificate()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(Subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new Oid(SetupService.ServerAuthEku) }, false));
        request.CertificateExtensions.Add(new X509Extension(
            CertificateTemplateExtensionReader.TemplateNameOid,
            CertificateTemplateExtensionReaderTests.EncodeTemplateName("WebServer"), false));
        using var certificate = request.CreateSelfSigned(Now.AddDays(-1), Now.AddDays(30));

        var facts = HttpsCertificateFollow.Describe(certificate);

        facts.Thumbprint.Should().Be(certificate.Thumbprint);
        facts.SubjectIdentity.Should().Be(Subject);
        facts.Template.Should().Be(new CertificateTemplateIdentity(null, null, null, "WebServer"));
        facts.HasPrivateKey.Should().BeTrue();
        facts.Archived.Should().BeFalse();
        facts.ServerAuthUsable.Should().BeTrue();
        facts.IsCertificateAuthority.Should().BeFalse();
    }

    [Fact]
    public void Describe_marks_a_client_only_certificate_and_a_ca()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(Subject, key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") }, false));
        using var certificate = request.CreateSelfSigned(Now.AddDays(-1), Now.AddDays(30));

        var facts = HttpsCertificateFollow.Describe(certificate);

        facts.ServerAuthUsable.Should().BeFalse();
        facts.IsCertificateAuthority.Should().BeTrue();
    }

    private string WriteOverlay(string? thumbprint)
    {
        var path = Path.Combine(_tempDir, CertusPaths.SettingsOverlayFileName);
        SettingsOverlay.Save(
            new SettingsOverlay.OverlaySettings(
                "ca01.corp.example.com\\Corp Issuing CA", "https://web01.corp.example.com:5001",
                HttpsCertificateThumbprint: thumbprint, HttpsCertificateTemplate: "WebServer"),
            path);
        return path;
    }

    [Fact]
    public void Repin_records_the_successor_and_keeps_every_other_key()
    {
        var path = WriteOverlay("aa aa");

        HttpsCertificateFollow.TryRepin(path, "AAAA", "BBBB", out var failure).Should().BeTrue();

        failure.Should().BeNull();
        var overlay = SettingsOverlay.Load(path);
        overlay.HttpsCertificateThumbprint.Should().Be("BBBB");
        overlay.HttpsCertificateTemplate.Should().Be("WebServer");
        overlay.CaConnectionString.Should().Be("ca01.corp.example.com\\Corp Issuing CA");
        overlay.ExternalUrl.Should().Be("https://web01.corp.example.com:5001");
    }

    [Fact]
    public void Repin_leaves_an_overlay_that_holds_another_thumbprint_alone()
    {
        // The overlay changed since boot read it, or the pinned thumbprint came
        // from somewhere else: either way it is not this follower's to replace.
        var path = WriteOverlay("CCCC");
        var before = File.ReadAllText(path);

        HttpsCertificateFollow.TryRepin(path, "AAAA", "BBBB", out _).Should().BeFalse();

        File.ReadAllText(path).Should().Be(before);
    }

    [Fact]
    public void Repin_never_creates_an_overlay()
    {
        var path = Path.Combine(_tempDir, CertusPaths.SettingsOverlayFileName);

        HttpsCertificateFollow.TryRepin(path, "AAAA", "BBBB", out var failure).Should().BeFalse();

        failure.Should().BeNull();
        File.Exists(path).Should().BeFalse();
    }

    [Fact]
    public void Repin_reports_an_overlay_it_cannot_read_and_leaves_it()
    {
        var path = Path.Combine(_tempDir, CertusPaths.SettingsOverlayFileName);
        File.WriteAllText(path, "{ not json");

        HttpsCertificateFollow.TryRepin(path, "AAAA", "BBBB", out var failure).Should().BeFalse();

        failure.Should().NotBeNull();
        File.ReadAllText(path).Should().Be("{ not json");
    }
}

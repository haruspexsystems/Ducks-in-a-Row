using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certus.Core.Setup;

namespace Certus.Core.Tests.Setup;

/// <summary>
/// Which certificates the monitor mode wizard may offer (issue #471). A certificate
/// the service cannot use would stop it binding HTTPS at the restart that applies
/// the choice, so every rule here is one the service would otherwise hit at startup.
/// </summary>
public class MachineCertificateChoicesTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;

    internal static X509Certificate2 Mint(
        string subject = "CN=web01.corp.example.com",
        string[]? dnsNames = null,
        string? ip = null,
        string[]? ekus = null,
        bool noEku = false,
        bool ca = false,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(ca, false, 0, ca));
        if (!noEku)
        {
            var oids = new OidCollection();
            foreach (var eku in ekus ?? [SetupService.ServerAuthEku])
                oids.Add(new Oid(eku));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(oids, false));
        }

        var san = new SubjectAlternativeNameBuilder();
        var anyName = false;
        foreach (var name in dnsNames ?? ["web01.corp.example.com"])
        {
            san.AddDnsName(name);
            anyName = true;
        }

        if (ip is not null)
        {
            san.AddIpAddress(IPAddress.Parse(ip));
            anyName = true;
        }

        if (anyName)
            request.CertificateExtensions.Add(san.Build());

        return request.CreateSelfSigned(notBefore ?? Now.AddDays(-1), notAfter ?? Now.AddDays(90));
    }

    [Fact]
    public void A_current_server_certificate_with_its_key_is_eligible()
    {
        using var certificate = Mint();

        MachineCertificateChoices.IsEligible(certificate, Now).Should().BeTrue();
    }

    [Fact]
    public void A_certificate_with_no_enhanced_key_usage_is_eligible()
    {
        // No EKU extension means valid for every purpose, which a TLS client accepts.
        using var certificate = Mint(noEku: true);

        MachineCertificateChoices.IsEligible(certificate, Now).Should().BeTrue();
    }

    [Fact]
    public void A_certificate_without_its_private_key_is_not_eligible()
    {
        using var withKey = Mint();
        using var publicOnly = X509CertificateLoader.LoadCertificate(withKey.RawData);

        MachineCertificateChoices.IsEligible(publicOnly, Now).Should().BeFalse();
    }

    [Fact]
    public void An_expired_certificate_is_not_eligible()
    {
        using var certificate = Mint(notBefore: Now.AddDays(-60), notAfter: Now.AddDays(-1));

        MachineCertificateChoices.IsEligible(certificate, Now).Should().BeFalse();
    }

    [Fact]
    public void A_certificate_not_yet_valid_is_not_eligible()
    {
        using var certificate = Mint(notBefore: Now.AddDays(1), notAfter: Now.AddDays(90));

        MachineCertificateChoices.IsEligible(certificate, Now).Should().BeFalse();
    }

    [Fact]
    public void A_client_authentication_certificate_is_not_eligible()
    {
        using var certificate = Mint(ekus: ["1.3.6.1.5.5.7.3.2"]);

        MachineCertificateChoices.IsEligible(certificate, Now).Should().BeFalse();
    }

    [Fact]
    public void A_ca_certificate_is_not_eligible()
    {
        using var certificate = Mint(ca: true);

        MachineCertificateChoices.IsEligible(certificate, Now).Should().BeFalse();
    }

    [Fact]
    public void The_services_own_fallback_certificate_is_not_offered()
    {
        using var certificate = Mint(subject: MachineCertificateChoices.SelfSignedFallbackSubject);

        MachineCertificateChoices.IsEligible(certificate, Now).Should().BeFalse();
    }

    [Fact]
    public void Rows_mark_coverage_put_covering_ones_first_and_drop_ineligible_ones()
    {
        using var other = Mint(subject: "CN=other.corp.example.com", dnsNames: ["other.corp.example.com"],
            notAfter: Now.AddDays(300));
        using var wildcard = Mint(subject: "CN=wildcard", dnsNames: ["*.corp.example.com"],
            notAfter: Now.AddDays(100));
        using var exact = Mint(notAfter: Now.AddDays(200));
        using var expired = Mint(notBefore: Now.AddDays(-60), notAfter: Now.AddDays(-1));

        var rows = MachineCertificateChoices.Describe(
            [other, wildcard, exact, expired], "web01.corp.example.com", exact.Thumbprint, Now);

        rows.Select(r => r.Thumbprint).Should().Equal(exact.Thumbprint, wildcard.Thumbprint, other.Thumbprint);
        rows.Select(r => r.CoversExternalHost).Should().Equal(true, true, false);
        rows[0].Configured.Should().BeTrue();
        rows[1].Configured.Should().BeFalse();
        rows[0].SelfSigned.Should().BeTrue();
        rows[0].Names.Should().Equal("web01.corp.example.com");
    }

    [Fact]
    public void An_ip_address_host_is_covered_by_an_ip_name()
    {
        using var certificate = Mint(dnsNames: [], ip: "192.0.2.10");

        MachineCertificateChoices.Describe([certificate], "192.0.2.10", null, Now)
            .Single().CoversExternalHost.Should().BeTrue();
    }
}

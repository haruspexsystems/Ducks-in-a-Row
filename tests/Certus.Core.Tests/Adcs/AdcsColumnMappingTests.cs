using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certus.Adcs;
using Certus.Core.Adcs;
using Microsoft.Extensions.Logging.Abstractions;

namespace Certus.Core.Tests.Adcs;

/// <summary>
/// Tests for the CA view row mapping in AdcsClient. Regression cover for the
/// dashboard bug where every synced certificate surfaced as Failed with no
/// requester and no request date: IEnumCERTVIEWCOLUMN::GetName returns table
/// qualified schema names for request table columns ("Request.Disposition"),
/// while the mapping looked values up by the unqualified constants, so the
/// disposition lookup missed and defaulted into the Failed branch.
/// </summary>
public class AdcsColumnMappingTests
{
    private static readonly IReadOnlyDictionary<string, string> EmptyTemplateMap =
        new Dictionary<string, string>();

    private static AdcsClient CreateClient() =>
        new("ca.example.com\\Example-CA", NullLogger<AdcsClient>.Instance);

    /// <summary>A complete issued row keyed the way ReadColumnValues stores it (normalized).</summary>
    private static Dictionary<string, object?> IssuedRow() => new()
    {
        ["RequestID"] = 7,
        ["SerialNumber"] = "44000000AB",
        ["CommonName"] = "web01.example.com",
        ["DistinguishedName"] = "CN=web01.example.com",
        ["CertificateTemplate"] = "WebServer",
        ["NotBefore"] = new DateTime(2026, 7, 1, 0, 0, 0, DateTimeKind.Utc),
        ["NotAfter"] = new DateTime(2028, 7, 1, 0, 0, 0, DateTimeKind.Utc),
        ["Disposition"] = 20,
        ["RequesterName"] = "HOME\\certus-svc",
        ["SubmittedWhen"] = new DateTime(2026, 7, 1, 0, 0, 0, DateTimeKind.Utc),
    };

    // ── NormalizeColumnName ─────────────────────────────────────────────

    [Theory]
    [InlineData("Request.Disposition", "Disposition")]
    [InlineData("Request.RequesterName", "RequesterName")]
    [InlineData("Request.SubmittedWhen", "SubmittedWhen")]
    [InlineData("Request.RevokedWhen", "RevokedWhen")]
    [InlineData("Request.RevokedReason", "RevokedReason")]
    [InlineData("Disposition", "Disposition")]
    [InlineData("SerialNumber", "SerialNumber")]
    [InlineData("A.B.C", "C")]
    public void NormalizeColumnName_StripsTableQualifier(string input, string expected)
    {
        AdcsClient.NormalizeColumnName(input).Should().Be(expected);
    }

    [Theory]
    [InlineData("Request.")]
    [InlineData("")]
    public void NormalizeColumnName_LeavesDegenerateNamesUnchanged(string input)
    {
        AdcsClient.NormalizeColumnName(input).Should().Be(input);
    }

    // ── MapToCertificateInfo ────────────────────────────────────────────

    [Theory]
    [InlineData(20, CertificateStatus.Issued)]
    [InlineData(21, CertificateStatus.Revoked)]
    [InlineData(9, CertificateStatus.Pending)]
    [InlineData(31, CertificateStatus.Denied)]
    [InlineData(30, CertificateStatus.Failed)]
    public void MapToCertificateInfo_TranslatesDbDispositions(int disposition, CertificateStatus expected)
    {
        var row = IssuedRow();
        row["Disposition"] = disposition;

        var info = CreateClient().MapToCertificateInfo(row, EmptyTemplateMap);

        info.Should().NotBeNull();
        info!.Status.Should().Be(expected);
    }

    [Fact]
    public void MapToCertificateInfo_PopulatesRequestFields()
    {
        var info = CreateClient().MapToCertificateInfo(IssuedRow(), EmptyTemplateMap);

        info.Should().NotBeNull();
        info!.RequestId.Should().Be(7);
        info.SerialNumber.Should().Be("44000000AB");
        info.Subject.Should().Be("CN=web01.example.com");
        info.Requestor.Should().Be("HOME\\certus-svc");
        info.RequestDate.Should().Be(new DateTime(2026, 7, 1, 0, 0, 0, DateTimeKind.Utc));
    }

    [Fact]
    public void MapToCertificateInfo_RevokedRow_PopulatesRevocationFields()
    {
        var revokedWhen = new DateTime(2026, 7, 5, 12, 0, 0, DateTimeKind.Utc);
        var row = IssuedRow();
        row["Disposition"] = 21;
        row["RevokedWhen"] = revokedWhen;
        row["RevokedReason"] = 4; // Superseded

        var info = CreateClient().MapToCertificateInfo(row, EmptyTemplateMap);

        info.Should().NotBeNull();
        info!.Status.Should().Be(CertificateStatus.Revoked);
        info.RevokedWhen.Should().Be(revokedWhen);
        info.RevokedReason.Should().Be(4);
    }

    [Fact]
    public void MapToCertificateInfo_IssuedRow_LeavesRevocationFieldsNull()
    {
        // The null tolerance contract for the IDispatch path: issued rows may
        // lack the revocation keys, carry explicit nulls (GetValue on a null
        // column), or even carry sentinel values on some CA builds. All three
        // shapes must map to null fields, because the sync relies on issued
        // rows carrying nulls to clear a released CertificateHold.
        var missingKeys = CreateClient().MapToCertificateInfo(IssuedRow(), EmptyTemplateMap);
        missingKeys.Should().NotBeNull();
        missingKeys!.RevokedWhen.Should().BeNull();
        missingKeys.RevokedReason.Should().BeNull();

        var explicitNulls = IssuedRow();
        explicitNulls["RevokedWhen"] = null;
        explicitNulls["RevokedReason"] = null;
        var info = CreateClient().MapToCertificateInfo(explicitNulls, EmptyTemplateMap);
        info.Should().NotBeNull();
        info!.RevokedWhen.Should().BeNull();
        info.RevokedReason.Should().BeNull();

        var sentinelValues = IssuedRow();
        sentinelValues["RevokedWhen"] = new DateTime(1601, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        sentinelValues["RevokedReason"] = 0;
        var sentinel = CreateClient().MapToCertificateInfo(sentinelValues, EmptyTemplateMap);
        sentinel.Should().NotBeNull();
        sentinel!.RevokedWhen.Should().BeNull();
        sentinel.RevokedReason.Should().BeNull();
    }

    [Fact]
    public void MapToCertificateInfo_MissingDispositionColumn_SkipsRow()
    {
        var row = IssuedRow();
        row.Remove("Disposition");

        CreateClient().MapToCertificateInfo(row, EmptyTemplateMap).Should().BeNull();
    }

    [Fact]
    public void MapToCertificateInfo_MissingOrZeroRequestId_SkipsRow()
    {
        var noId = IssuedRow();
        noId.Remove("RequestID");
        CreateClient().MapToCertificateInfo(noId, EmptyTemplateMap).Should().BeNull();

        var zeroId = IssuedRow();
        zeroId["RequestID"] = 0;
        CreateClient().MapToCertificateInfo(zeroId, EmptyTemplateMap).Should().BeNull();
    }

    [Fact]
    public void MapToCertificateInfo_RawCertificate_PopulatesSans()
    {
        var der = CreateCertificate("CN=web01.example.com", san =>
        {
            san.AddDnsName("web01.example.com");
            san.AddDnsName("alt.example.com");
            san.AddIpAddress(IPAddress.Parse("10.0.0.5"));
        });
        var row = IssuedRow();
        row["RawCertificate"] = Convert.ToBase64String(der);

        var info = CreateClient().MapToCertificateInfo(row, EmptyTemplateMap);

        info.Should().NotBeNull();
        info!.SubjectAlternativeNames.Should().Be(
            "dns:web01.example.com, dns:alt.example.com, ip:10.0.0.5");
    }

    [Fact]
    public void MapToCertificateInfo_EmptyDbSubjectColumns_FallsBackToCertificateSubject()
    {
        // ACME style rows: the CSR carried no subject DN in the CA database
        // columns, but the issued certificate itself has one.
        var der = CreateCertificate("CN=acme.example.com", san => san.AddDnsName("acme.example.com"));
        var row = IssuedRow();
        row["CommonName"] = "";
        row["DistinguishedName"] = "";
        row["RawCertificate"] = Convert.ToBase64String(der);

        var info = CreateClient().MapToCertificateInfo(row, EmptyTemplateMap);

        info.Should().NotBeNull();
        info!.Subject.Should().Be("CN=acme.example.com");
        info.SubjectAlternativeNames.Should().Be("dns:acme.example.com");
    }

    [Fact]
    public void MapToCertificateInfo_SanOnlyCertificate_FallsBackToFirstSan()
    {
        // SAN only ACME issuance: no subject in the CA columns and none in
        // the certificate either. The first SAN becomes the display subject,
        // stored bare with no "CN=" prefix.
        var der = CreateCertificate("", san =>
        {
            san.AddDnsName("linux.manual2025.local");
            san.AddDnsName("alt.manual2025.local");
        });
        var row = IssuedRow();
        row["CommonName"] = "";
        row["DistinguishedName"] = "";
        row["RawCertificate"] = Convert.ToBase64String(der);

        var info = CreateClient().MapToCertificateInfo(row, EmptyTemplateMap);

        info.Should().NotBeNull();
        info!.Subject.Should().Be("linux.manual2025.local");
        info.SubjectAlternativeNames.Should().Be(
            "dns:linux.manual2025.local, dns:alt.manual2025.local");
    }

    [Fact]
    public void MapToCertificateInfo_EmptyDnColumn_FallsBackToCommonNameColumn()
    {
        // The CA can return an empty string rather than null for
        // DistinguishedName; the CommonName column must still win over
        // nothing.
        var row = IssuedRow();
        row["DistinguishedName"] = "";
        row["CommonName"] = "web01.example.com";
        row.Remove("RawCertificate");

        var info = CreateClient().MapToCertificateInfo(row, EmptyTemplateMap);

        info.Should().NotBeNull();
        info!.Subject.Should().Be("web01.example.com");
    }

    [Theory]
    [InlineData("dns:a.example.com, dns:b.example.com", "a.example.com")]
    [InlineData("ip:10.0.0.5", "10.0.0.5")]
    [InlineData("ip:2001:db8::1", "2001:db8::1")]
    [InlineData("unlabeled.example.com", "unlabeled.example.com")]
    public void FirstSanDisplayName_StripsLabels(string sans, string expected)
    {
        AdcsClient.FirstSanDisplayName(sans).Should().Be(expected);
    }

    [Fact]
    public void MapToCertificateInfo_UndecodableRawCertificate_KeepsRowWithoutSans()
    {
        var row = IssuedRow();
        row["RawCertificate"] = "not base64 at all!!!";

        var info = CreateClient().MapToCertificateInfo(row, EmptyTemplateMap);

        info.Should().NotBeNull();
        info!.Status.Should().Be(CertificateStatus.Issued);
        info.SubjectAlternativeNames.Should().BeNull();
    }

    // ── ExtractSubjectAndSans ───────────────────────────────────────────

    [Fact]
    public void ExtractSubjectAndSans_NoSanExtension_ReturnsNullSans()
    {
        var der = CreateCertificate("CN=plain.example.com", sanSetup: null);

        var (subject, sans) = AdcsClient.ExtractSubjectAndSans(der);

        subject.Should().Be("CN=plain.example.com");
        sans.Should().BeNull();
    }

    [Fact]
    public void ExtractSubjectAndSans_SanOnlyCertificate_ReturnsEmptySubjectAndSans()
    {
        // A SAN only certificate (typical ACME issuance): empty subject DN,
        // identity carried entirely in the SAN extension.
        var der = CreateCertificate("", san => san.AddDnsName("linux.example.com"));

        var (subject, sans) = AdcsClient.ExtractSubjectAndSans(der);

        subject.Should().BeEmpty();
        sans.Should().Be("dns:linux.example.com");
    }

    private static byte[] CreateCertificate(string subject, Action<SubjectAlternativeNameBuilder>? sanSetup)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            new X500DistinguishedName(subject),
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        if (sanSetup != null)
        {
            var builder = new SubjectAlternativeNameBuilder();
            sanSetup(builder);
            request.CertificateExtensions.Add(builder.Build());
        }

        using var cert = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(30));
        return cert.Export(X509ContentType.Cert);
    }
}

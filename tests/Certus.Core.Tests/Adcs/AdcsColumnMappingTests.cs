using System.Formats.Asn1;
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
    [InlineData("Request.DispositionMessage", "DispositionMessage")]
    [InlineData("Request.StatusCode", "StatusCode")]
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

    [Theory]
    [InlineData("Request.CommonName", "Request.CommonName")]
    [InlineData("Request.DistinguishedName", "Request.DistinguishedName")]
    // Canonicalized, not echoed back: the match is case insensitive but the
    // dictionary the key lands in is not, and the mapping reads it back by the
    // exact literal. Echoing the caller's spelling would file the value under a
    // key nothing looks up, and that miss is invisible even to the collision
    // warning, because it is a distinct key rather than a duplicate.
    [InlineData("request.commonname", "Request.CommonName")]
    [InlineData("REQUEST.DISTINGUISHEDNAME", "Request.DistinguishedName")]
    public void NormalizeColumnName_KeepsTheQualifierOnTheCollidingColumns(
        string input, string expected)
    {
        // The CA schema carries the subject twice and the probe confirmed on the
        // lab CA (2026-08-03) that GetName returns these two qualified while the
        // issued pair comes back bare. Stripping the qualifier would key both
        // onto "CommonName", and ReadColumnValues keeps the first, which on the
        // observed registration order is the issued one. The request name would
        // then vanish with nothing in the log to say so (issue #186).
        AdcsClient.NormalizeColumnName(input).Should().Be(expected);
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

    // ── DispositionMessage and StatusCode (issue #151) ──────────────────

    [Theory]
    [InlineData(9, CertificateStatus.Pending)]
    [InlineData(31, CertificateStatus.Denied)]
    [InlineData(30, CertificateStatus.Failed)]
    public void MapToCertificateInfo_RequestRow_PopulatesDispositionMessage(
        int disposition, CertificateStatus expectedStatus)
    {
        var row = IssuedRow();
        row["Disposition"] = disposition;
        row["DispositionMessage"] = "Taken Under Submission";
        row["StatusCode"] = unchecked((int)0x80094801);

        var info = CreateClient().MapToCertificateInfo(row, EmptyTemplateMap);

        info.Should().NotBeNull();
        info!.Status.Should().Be(expectedStatus);
        info.DispositionMessage.Should().Be("Taken Under Submission");
        info.StatusCode.Should().Be(unchecked((int)0x80094801));
    }

    [Theory]
    [InlineData(20)] // Issued
    [InlineData(21)] // Revoked
    public void MapToCertificateInfo_CertificateRow_LeavesDispositionFieldsNull(int disposition)
    {
        // The sentinel case, and the one most likely to regress. An issued row
        // carries "Issued" and a zero status code on the IDispatch path; letting
        // those through would leave a stale explanation behind when a pending
        // request is finally approved, because UpdateEntity overwrites straight.
        var row = IssuedRow();
        row["Disposition"] = disposition;
        row["DispositionMessage"] = "Issued";
        row["StatusCode"] = 0;

        var info = CreateClient().MapToCertificateInfo(row, EmptyTemplateMap);

        info.Should().NotBeNull();
        info!.DispositionMessage.Should().BeNull();
        info.StatusCode.Should().BeNull();
    }

    [Fact]
    public void MapToCertificateInfo_RequestRow_ToleratesMissingAndEmptyValues()
    {
        // A row where the columns are absent, null, or blank must render nothing
        // rather than an empty labelled field, and must not fail the sync.
        var missingKeys = IssuedRow();
        missingKeys["Disposition"] = 9;
        var absent = CreateClient().MapToCertificateInfo(missingKeys, EmptyTemplateMap);
        absent.Should().NotBeNull();
        absent!.DispositionMessage.Should().BeNull();
        absent.StatusCode.Should().BeNull();

        var explicitNulls = IssuedRow();
        explicitNulls["Disposition"] = 9;
        explicitNulls["DispositionMessage"] = null;
        explicitNulls["StatusCode"] = null;
        var nulls = CreateClient().MapToCertificateInfo(explicitNulls, EmptyTemplateMap);
        nulls.Should().NotBeNull();
        nulls!.DispositionMessage.Should().BeNull();
        nulls.StatusCode.Should().BeNull();

        var blank = IssuedRow();
        blank["Disposition"] = 9;
        blank["DispositionMessage"] = "   ";
        blank["StatusCode"] = 0; // zero is success and carries no information
        var whitespace = CreateClient().MapToCertificateInfo(blank, EmptyTemplateMap);
        whitespace.Should().NotBeNull();
        whitespace!.DispositionMessage.Should().BeNull();
        whitespace.StatusCode.Should().BeNull();
    }

    // The sanitizer itself is covered by CertificateTextSanitizerTests; what
    // belongs here is which sources the mapping runs through it.

    // Composed with a cast rather than an escape sequence, so every string
    // literal in this file stays plain readable text.
    private const char Esc = (char)0x1b;

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

    // ── Request subject columns (issue #186) ────────────────────────────

    /// <summary>
    /// A denied row in the shape the lab CA actually returned on 2026-08-03:
    /// no serial, no certificate blob, no issued DistinguishedName, but the
    /// issued CommonName filled with a copy of the request CN, because a policy
    /// module denial happens after the CA has parsed the subject.
    /// </summary>
    private static Dictionary<string, object?> DeniedRow() => new()
    {
        ["RequestID"] = 31,
        ["SerialNumber"] = null,
        ["CommonName"] = "denied.example.com",
        ["DistinguishedName"] = null,
        ["CertificateTemplate"] = "WebServer",
        ["Disposition"] = 31,
        ["RequesterName"] = "LAB\\alice",
        ["Request.CommonName"] = "denied.example.com",
        ["Request.DistinguishedName"] = "CN=denied.example.com",
    };

    [Theory]
    [InlineData(9)]  // Pending
    [InlineData(31)] // Denied
    [InlineData(30)] // Failed
    public void MapToCertificateInfo_RequestRow_PrefersTheRequestedDn(int disposition)
    {
        // Nothing was signed on these rows, so what the requester asked for is
        // the authoritative name, and it is the fuller DN rather than the bare
        // CN the issued column happens to carry.
        var row = DeniedRow();
        row["Disposition"] = disposition;

        var info = CreateClient().MapToCertificateInfo(row, EmptyTemplateMap);

        info.Should().NotBeNull();
        info!.Subject.Should().Be("CN=denied.example.com");
    }

    [Fact]
    public void MapToCertificateInfo_RequestRow_FallsBackThroughEveryNameSource()
    {
        // Each source removed in turn: request DN, then request CN, then the
        // issued columns, then nothing at all. The CA hands back empty strings
        // as readily as nulls, so both shapes have to fall through.
        var row = DeniedRow();
        row["Request.DistinguishedName"] = "";
        CreateClient().MapToCertificateInfo(row, EmptyTemplateMap)!
            .Subject.Should().Be("denied.example.com", "the request CN is next");

        row["Request.CommonName"] = null;
        CreateClient().MapToCertificateInfo(row, EmptyTemplateMap)!
            .Subject.Should().Be("denied.example.com", "the issued CN still carries a copy");

        row["CommonName"] = "";
        CreateClient().MapToCertificateInfo(row, EmptyTemplateMap)!
            .Subject.Should().BeEmpty("nothing named it, and the row must still survive");
    }

    [Fact]
    public void MapToCertificateInfo_IssuedRow_NeverTakesTheRequestedName()
    {
        // The precedence guard. On an enrollee supplies subject template the CA
        // policy can rewrite the subject, so an issued certificate must display
        // what was signed and never what was asked for.
        var row = IssuedRow();
        row["Request.CommonName"] = "what-the-requester-asked-for.example.com";
        row["Request.DistinguishedName"] = "CN=what-the-requester-asked-for.example.com";

        var info = CreateClient().MapToCertificateInfo(row, EmptyTemplateMap);

        info.Should().NotBeNull();
        info!.Subject.Should().Be("CN=web01.example.com");
    }

    [Fact]
    public void MapToCertificateInfo_RevokedRow_NeverTakesTheRequestedName()
    {
        var row = IssuedRow();
        row["Disposition"] = 21;
        row["Request.DistinguishedName"] = "CN=what-the-requester-asked-for.example.com";

        CreateClient().MapToCertificateInfo(row, EmptyTemplateMap)!
            .Subject.Should().Be("CN=web01.example.com");
    }

    [Fact]
    public void MapToCertificateInfo_RequestRow_SanitizesTheRequestedName()
    {
        // The request columns are the raw CSR subject, captured before any CA
        // policy ran; on a denied row it is by definition a name the CA refused.
        // A right to left override in it makes an admin read a different
        // hostname than the one that was requested.
        var rlo = (char)0x202e;
        var row = DeniedRow();
        row["Request.DistinguishedName"] = "CN=" + rlo + "moc.live" + Esc + "[0m";

        var info = CreateClient().MapToCertificateInfo(row, EmptyTemplateMap);

        info.Should().NotBeNull();
        info!.Subject.Should().Be("CN=moc.live[0m");
    }

    [Fact]
    public void MapToCertificateInfo_RequestRow_SanitizesTheIssuedFallbackToo()
    {
        // The gap a review caught. On a request row the issued columns hold the
        // CA's own copy of the same unvetted CSR subject, so sanitizing only the
        // request pair left the spoof reachable through the fallback whenever
        // the request pair came back blank and the copy did not.
        var rlo = (char)0x202e;
        var row = DeniedRow();
        row["Request.DistinguishedName"] = "";
        row["Request.CommonName"] = null;
        row["CommonName"] = rlo + "moc.live";

        var info = CreateClient().MapToCertificateInfo(row, EmptyTemplateMap);

        info.Should().NotBeNull();
        info!.Subject.Should().Be("moc.live");
    }

    [Fact]
    public void MapToCertificateInfo_IssuedRow_BoundsTheSubjectToTheColumn()
    {
        // Was LeavesTheIssuedSubjectAlone, which pinned the exposure issue #224
        // was filed for: this asserted that a 9003 character subject reached the
        // 500 character indexed column intact, because SQLite does not enforce a
        // declared width and nothing else in the chain did either.
        var row = IssuedRow();
        row["DistinguishedName"] = "CN=" + new string('x', 9000);
        row.Remove("RawCertificate");

        var info = CreateClient().MapToCertificateInfo(row, EmptyTemplateMap);

        info.Should().NotBeNull();
        info!.Subject.Should().HaveLength(CertificateTextSanitizer.MaxSubjectLength);
    }

    [Fact]
    public void MapToCertificateInfo_IssuedRow_SanitizesTheIssuedSubject()
    {
        // Issue #224 proper. On a template with enrollee supplies subject the CN
        // is whatever the CSR asked for and the CA signs it rather than rewriting
        // it, so a signature does not make the name safe to render.
        var rlo = (char)0x202e;
        var row = IssuedRow();
        row["DistinguishedName"] = "CN=" + rlo + "moc.live";
        row.Remove("RawCertificate");

        var info = CreateClient().MapToCertificateInfo(row, EmptyTemplateMap);

        info.Should().NotBeNull();
        info!.Subject.Should().Be("CN=moc.live");
    }

    [Fact]
    public void SubjectRendering_DoesNotReorderRdns()
    {
        // The measurement the CN preserving truncation rests on, pinned here
        // rather than left as a claim in a comment. X509Certificate2.Subject is a
        // straight passthrough of the encoded RDN sequence: it does not move the
        // CN to the front. ADCS conventionally encodes general to specific, so a
        // real issued subject has the CN last, which is exactly where a plain tail
        // cut would destroy it. If a future runtime starts reversing the order,
        // this fails and the sanitizer's reasoning needs revisiting.
        var generalToSpecific = "C=US, S=Washington, O=Example Corp, OU=IT, CN=leaf.example.com";
        var der = CreateCertificate(generalToSpecific, null);

        var parsed = CertificateDerParser.Parse(der);

        parsed.Should().NotBeNull();
        parsed!.Subject.Should().Be(generalToSpecific);
        parsed.Subject.Should().NotStartWith("CN=",
            "the CN is encoded last and nothing reorders it on the way back");
    }

    [Fact]
    public void MapToCertificateInfo_IssuedRow_StripsTagCharactersFromTheIssuedSubject()
    {
        // Where issue #228 and issue #224 meet. The tag block encodes arbitrary
        // ASCII invisibly, and before #224 the issued columns never reached the
        // sanitizer at all, so widening the scan there did nothing for a signed
        // subject. Both changes are needed for this row to come out clean.
        var tagged = "CN=host" + char.ConvertFromUtf32(0xE0020) + "name.example.com";
        var row = IssuedRow();
        row["DistinguishedName"] = tagged;
        row.Remove("RawCertificate");

        var info = CreateClient().MapToCertificateInfo(row, EmptyTemplateMap);

        info.Should().NotBeNull();
        info!.Subject.Should().Be("CN=hostname.example.com");
    }

    [Fact]
    public void MapToCertificateInfo_RevokedRow_SanitizesTheIssuedSubject()
    {
        // Revoked is its own arm of the status switch and its own precedence
        // branch, so it gets its own assertion rather than riding on the issued
        // one.
        var rlo = (char)0x202e;
        var row = IssuedRow();
        row["Disposition"] = 21;
        row["DistinguishedName"] = "CN=" + rlo + "moc.live";
        row.Remove("RawCertificate");

        var info = CreateClient().MapToCertificateInfo(row, EmptyTemplateMap);

        info.Should().NotBeNull();
        info!.Subject.Should().Be("CN=moc.live");
    }

    [Fact]
    public void MapToCertificateInfo_IssuedRow_SanitizesTheDerSubjectFallback()
    {
        // The fallback that looks safe and is not. It reads the signed subject
        // through X509Certificate2, which passes format characters straight
        // through, and unlike the columns above it is reached on every
        // disposition rather than only issued ones.
        var rlo = (char)0x202e;
        var der = CreateCertificate("CN=" + rlo + "moc.live", null);
        var row = IssuedRow();
        row["DistinguishedName"] = null;
        row["CommonName"] = null;
        row["RawCertificate"] = Convert.ToBase64String(der);

        var info = CreateClient().MapToCertificateInfo(row, EmptyTemplateMap);

        info.Should().NotBeNull();
        info!.Subject.Should().Be("CN=moc.live");
    }

    [Fact]
    public void MapToCertificateInfo_IssuedRow_BoundsTheSanFallbackToTheColumn()
    {
        // The SAN list is capped to the 2000 character SubjectAlternativeNames
        // column, which is four times what Subject holds, so a single long entry
        // overflows on its own. Written by hand rather than through
        // SubjectAlternativeNameBuilder, which enforces the DNS length limits the
        // reader does not; see CreateCertificateWithRawDnsSan.
        var der = CreateCertificateWithRawDnsSan("", new string('a', 900) + ".example.com");
        var row = IssuedRow();
        row["DistinguishedName"] = null;
        row["CommonName"] = null;
        row["RawCertificate"] = Convert.ToBase64String(der);

        var info = CreateClient().MapToCertificateInfo(row, EmptyTemplateMap);

        info.Should().NotBeNull();
        info!.Subject.Should().HaveLength(CertificateTextSanitizer.MaxSubjectLength);
    }

    [Fact]
    public void MapToCertificateInfo_IssuedRow_AllJunkPrimarySourceFallsThroughToTheDer()
    {
        // Pins the per candidate design against a later simplification that
        // sanitizes once at the end. A column that is nothing but format
        // characters has to sanitize to null and keep falling through the chain;
        // sanitizing a single already chosen value would instead let the junk win
        // the FirstNonBlank and collapse the fallbacks behind it.
        var rlo = (char)0x202e;
        var zwsp = (char)0x200b;
        var der = CreateCertificate("CN=real.example.com", null);
        var row = IssuedRow();
        row["DistinguishedName"] = rlo.ToString() + zwsp;
        row["CommonName"] = zwsp.ToString();
        row["RawCertificate"] = Convert.ToBase64String(der);

        var info = CreateClient().MapToCertificateInfo(row, EmptyTemplateMap);

        info.Should().NotBeNull();
        info!.Subject.Should().Be("CN=real.example.com");
    }

    [Fact]
    public void MapToCertificateInfo_RequestRow_BoundsTheRequestedNameToTheColumn()
    {
        // The CA schema allows 8192 characters for this column; SyncedCertificate
        // stores 500 and indexes it, and SQLite would not refuse the overflow.
        var row = DeniedRow();
        row["Request.DistinguishedName"] = "CN=" + new string('x', 9000);

        var info = CreateClient().MapToCertificateInfo(row, EmptyTemplateMap);

        info.Should().NotBeNull();
        info!.Subject.Should().HaveLength(CertificateTextSanitizer.MaxSubjectLength);
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
        info.CryptoDetail.Should().BeNull();
    }

    [Fact]
    public void MapToCertificateInfo_RawCertificate_PopulatesCryptoDetail()
    {
        // The certificate blob the view already returns is the only source for
        // this, and it is parsed once alongside the SANs. Values themselves are
        // covered in CertificateDerParserTests; here we assert the wiring.
        var der = CreateCertificate("CN=web01.example.com", san => san.AddDnsName("web01.example.com"));
        var row = IssuedRow();
        row["RawCertificate"] = Convert.ToBase64String(der);

        var info = CreateClient().MapToCertificateInfo(row, EmptyTemplateMap);

        info.Should().NotBeNull();
        info!.CryptoDetail.Should().NotBeNull();
        info.CryptoDetail!.KeyAlgorithm.Should().Be("RSA");
        info.CryptoDetail.KeySizeBits.Should().Be(2048);
        info.CryptoDetail.Sha256Thumbprint.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void MapToCertificateInfo_NoRawCertificate_LeavesCryptoDetailNull()
    {
        // The shape the revoked pass can hand back. Null means "this pass had
        // nothing to say", which the sync relies on to avoid blanking detail it
        // captured from the issued pass.
        var row = IssuedRow();
        row.Remove("RawCertificate");

        var info = CreateClient().MapToCertificateInfo(row, EmptyTemplateMap);

        info.Should().NotBeNull();
        info!.CryptoDetail.Should().BeNull();
    }

    // The DER parse itself now lives in CertificateDerParser and is covered by
    // CertificateDerParserTests; what belongs here is that the mapping wires it
    // through, which the two CryptoDetail cases above assert.

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

    /// <summary>
    /// A certificate carrying one dNSName written straight into the extension,
    /// bypassing SubjectAlternativeNameBuilder.
    ///
    /// The builder runs the name through IDN mapping, which enforces the DNS
    /// label and total length limits, so it cannot produce a name long enough to
    /// overflow the Subject column. A certificate authority is not obliged to
    /// enforce those limits, and the reader does not re-check them, so the
    /// oversized name has to be encoded by hand to exercise the path at all.
    /// </summary>
    private static byte[] CreateCertificateWithRawDnsSan(string subject, string dnsName)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            new X500DistinguishedName(subject),
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        // SubjectAltName ::= GeneralNames ::= SEQUENCE OF GeneralName, where a
        // dNSName is context specific tag 2 wrapping an IA5String.
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteCharacterString(
                UniversalTagNumber.IA5String,
                dnsName,
                new Asn1Tag(TagClass.ContextSpecific, 2));
        }

        request.CertificateExtensions.Add(
            new X509Extension("2.5.29.17", writer.Encode(), critical: false));

        using var cert = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(30));
        return cert.Export(X509ContentType.Cert);
    }
}

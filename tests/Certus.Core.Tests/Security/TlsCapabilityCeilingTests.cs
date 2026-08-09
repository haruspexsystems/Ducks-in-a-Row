using System.Security.Cryptography.X509Certificates;
using Certus.Core.Security;

namespace Certus.Core.Tests.Security;

public class TlsCapabilityCeilingTests
{
    private static CertificateCapability Capability(
        IReadOnlyList<string>? ekus = null,
        X509KeyUsageFlags? keyUsage = null,
        bool? isCa = null) => new(ekus, keyUsage, isCa);

    // ── The allowed shapes ──────────────────────────────────────────────

    [Fact]
    public void Evaluate_ServerAuthOnly_Allows()
    {
        var verdict = TlsCapabilityCeiling.Evaluate(Capability(ekus: [TlsEkuOids.ServerAuth]));

        verdict.Should().Be(CeilingVerdict.Ok);
    }

    [Fact]
    public void Evaluate_ClientAuthOnly_Allows()
    {
        // Device attestation templates are client auth shaped; the ceiling
        // must not break them.
        var verdict = TlsCapabilityCeiling.Evaluate(Capability(ekus: [TlsEkuOids.ClientAuth]));

        verdict.Should().Be(CeilingVerdict.Ok);
    }

    [Fact]
    public void Evaluate_ServerAndClientAuth_Allows()
    {
        var verdict = TlsCapabilityCeiling.Evaluate(
            Capability(ekus: [TlsEkuOids.ServerAuth, TlsEkuOids.ClientAuth]));

        verdict.Should().Be(CeilingVerdict.Ok);
    }

    [Fact]
    public void Evaluate_AbsentKeyUsageAndBasicConstraints_Allows()
    {
        // Both extensions are routinely absent on real TLS leaves; their
        // absence must not block when the EKU set is inside the ceiling.
        var verdict = TlsCapabilityCeiling.Evaluate(
            Capability(ekus: [TlsEkuOids.ServerAuth], keyUsage: null, isCa: null));

        verdict.Allowed.Should().BeTrue();
    }

    [Fact]
    public void Evaluate_OrdinaryTlsKeyUsage_Allows()
    {
        var verdict = TlsCapabilityCeiling.Evaluate(Capability(
            ekus: [TlsEkuOids.ServerAuth],
            keyUsage: X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment));

        verdict.Allowed.Should().BeTrue();
    }

    // ── The refusals ────────────────────────────────────────────────────

    [Fact]
    public void Evaluate_NullEkuList_RefusesAsNoEku()
    {
        var verdict = TlsCapabilityCeiling.Evaluate(Capability(ekus: null));

        verdict.Allowed.Should().BeFalse();
        verdict.ReasonCode.Should().Be("no-eku");
        verdict.Message.Should().Contain("every purpose");
    }

    [Fact]
    public void Evaluate_EmptyEkuList_RefusesAsNoEku()
    {
        var verdict = TlsCapabilityCeiling.Evaluate(Capability(ekus: []));

        verdict.Allowed.Should().BeFalse();
        verdict.ReasonCode.Should().Be("no-eku");
    }

    [Theory]
    [InlineData(TlsEkuOids.AnyPurpose, "any purpose")]
    [InlineData(TlsEkuOids.EnrollmentAgent, "certificate request agent")]
    [InlineData(TlsEkuOids.SmartCardLogon, "smart card logon")]
    [InlineData(TlsEkuOids.KdcAuthentication, "KDC authentication")]
    [InlineData(TlsEkuOids.CodeSigning, "code signing")]
    [InlineData(TlsEkuOids.OcspSigning, "OCSP signing")]
    [InlineData(TlsEkuOids.TimeStamping, "time stamping")]
    [InlineData(TlsEkuOids.KeyRecoveryAgent, "key recovery agent")]
    [InlineData(TlsEkuOids.Efs, "encrypting file system")]
    [InlineData(TlsEkuOids.CaExchange, "CA exchange")]
    public void Evaluate_BlacklistedEku_RefusesNamingTheOffender(string oid, string name)
    {
        // A dangerous EKU refuses even when it rides next to a permitted one,
        // and the message names both the label and the OID so the admin knows
        // exactly which usage tripped the guard.
        var verdict = TlsCapabilityCeiling.Evaluate(
            Capability(ekus: [TlsEkuOids.ServerAuth, oid]));

        verdict.Allowed.Should().BeFalse();
        verdict.ReasonCode.Should().Be("blacklisted-eku");
        verdict.Message.Should().Contain(name).And.Contain(oid);
    }

    [Fact]
    public void Evaluate_UnknownEku_RefusesAsOutsideTheCeiling()
    {
        // The subset rule: an OID the blacklist has never heard of still
        // refuses, so a custom usage can never widen what Ducks touches.
        var verdict = TlsCapabilityCeiling.Evaluate(
            Capability(ekus: [TlsEkuOids.ServerAuth, "1.2.3.4.5.6"]));

        verdict.Allowed.Should().BeFalse();
        verdict.ReasonCode.Should().Be("eku-outside-ceiling");
        verdict.Message.Should().Contain("1.2.3.4.5.6");
    }

    [Theory]
    [InlineData(X509KeyUsageFlags.KeyCertSign)]
    [InlineData(X509KeyUsageFlags.CrlSign)]
    [InlineData(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.DigitalSignature)]
    public void Evaluate_SigningKeyUsage_Refuses(X509KeyUsageFlags keyUsage)
    {
        var verdict = TlsCapabilityCeiling.Evaluate(
            Capability(ekus: [TlsEkuOids.ServerAuth], keyUsage: keyUsage));

        verdict.Allowed.Should().BeFalse();
        verdict.ReasonCode.Should().Be("key-usage");
    }

    [Fact]
    public void Evaluate_CaCertificate_Refuses()
    {
        var verdict = TlsCapabilityCeiling.Evaluate(
            Capability(ekus: [TlsEkuOids.ServerAuth], isCa: true));

        verdict.Allowed.Should().BeFalse();
        verdict.ReasonCode.Should().Be("ca-certificate");
    }

    [Fact]
    public void Evaluate_ExplicitlyNotACa_DoesNotRefuseOnBasicConstraints()
    {
        var verdict = TlsCapabilityCeiling.Evaluate(
            Capability(ekus: [TlsEkuOids.ServerAuth], isCa: false));

        verdict.Allowed.Should().BeTrue();
    }

    // ── Precedence ──────────────────────────────────────────────────────

    [Fact]
    public void Evaluate_CaCertificateWinsOverEveryOtherReason()
    {
        // The message names the most serious offence when several apply.
        var verdict = TlsCapabilityCeiling.Evaluate(Capability(
            ekus: [TlsEkuOids.EnrollmentAgent],
            keyUsage: X509KeyUsageFlags.KeyCertSign,
            isCa: true));

        verdict.ReasonCode.Should().Be("ca-certificate");
    }

    [Fact]
    public void Evaluate_BlacklistWinsOverTheSubsetRule()
    {
        // Both a blacklisted and an unknown OID are present; the named one
        // makes the better message and must be the one reported.
        var verdict = TlsCapabilityCeiling.Evaluate(
            Capability(ekus: ["1.2.3.4.5.6", TlsEkuOids.CodeSigning]));

        verdict.ReasonCode.Should().Be("blacklisted-eku");
    }
}

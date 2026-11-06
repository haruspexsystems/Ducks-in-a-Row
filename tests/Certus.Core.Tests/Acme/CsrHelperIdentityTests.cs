using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certus.Core.Acme.Services;
using Certus.Core.Tests.Acme.Attestation;

namespace Certus.Core.Tests.Acme;

/// <summary>
/// Tests for <see cref="CsrHelper.ExtractCsrIdentity"/>. The load bearing
/// properties: the PermanentIdentifier SAN is reassembled into the ACME
/// grammar string, and every SAN entry the parser does not positively
/// recognize surfaces as HasOtherSanEntries rather than vanishing, because
/// ADCS forwards the raw CSR and a silently skipped name would still land
/// in the issued certificate.
/// </summary>
public class CsrHelperIdentityTests
{
    private const string Serial = "SN-0001";
    private const string Assigner = "1.3.6.1.4.1.99999.1";

    private static ECDsa NewKey() => ECDsa.Create(ECCurve.NamedCurves.nistP256);

    [Fact]
    public void Extract_PermanentIdentifierSan_ReassemblesGrammarForm()
    {
        using var key = NewKey();
        var csr = DeviceCsrBuilder.Build(key, "O=Device Fleet", Serial, Assigner);

        var identity = CsrHelper.ExtractCsrIdentity(csr);

        identity.PermanentIdentifiers.Should().Equal($"{Serial}/{Assigner}");
        identity.SubjectCns.Should().BeEmpty();
        identity.DnsNames.Should().BeEmpty();
        identity.HasOtherSanEntries.Should().BeFalse();
    }

    [Fact]
    public void Extract_PermanentIdentifierWithoutAssigner_YieldsBareValue()
    {
        using var key = NewKey();
        var csr = DeviceCsrBuilder.Build(key, "O=Device Fleet", Serial);

        var identity = CsrHelper.ExtractCsrIdentity(csr);

        identity.PermanentIdentifiers.Should().Equal(Serial);
    }

    [Fact]
    public void Extract_CnOnly_YieldsCnAndNoSans()
    {
        // The Apple shape: subject CN carries the ClientIdentifier, no SAN
        // extension at all (Apple CSRs cannot express the otherName).
        using var key = NewKey();
        var csr = DeviceCsrBuilder.Build(key, $"CN={Serial}");

        var identity = CsrHelper.ExtractCsrIdentity(csr);

        identity.SubjectCns.Should().Equal(Serial);
        identity.PermanentIdentifiers.Should().BeEmpty();
        identity.HasOtherSanEntries.Should().BeFalse();
    }

    [Fact]
    public void Extract_CnAndSan_YieldsBoth()
    {
        using var key = NewKey();
        var csr = DeviceCsrBuilder.Build(key, $"CN={Serial}", Serial);

        var identity = CsrHelper.ExtractCsrIdentity(csr);

        identity.SubjectCns.Should().Equal(Serial);
        identity.PermanentIdentifiers.Should().Equal(Serial);
    }

    [Fact]
    public void Extract_NeitherCnNorSan_YieldsEmptyIdentity()
    {
        using var key = NewKey();
        var csr = DeviceCsrBuilder.Build(key, "O=Device Fleet");

        var identity = CsrHelper.ExtractCsrIdentity(csr);

        identity.SubjectCns.Should().BeEmpty();
        identity.PermanentIdentifiers.Should().BeEmpty();
        identity.DnsNames.Should().BeEmpty();
        identity.HasOtherSanEntries.Should().BeFalse();
    }

    [Fact]
    public void Extract_DnsNamesAlongsidePermanentIdentifier_ListsBoth()
    {
        // The probe's Run C shape: otherName plus a dNSName. Both surface,
        // so the finalize check can refuse the DNS name.
        using var key = NewKey();
        var csr = DeviceCsrBuilder.Build(
            key, "O=Device Fleet", Serial, null, "device.example.com");

        var identity = CsrHelper.ExtractCsrIdentity(csr);

        identity.PermanentIdentifiers.Should().Equal(Serial);
        identity.DnsNames.Should().Equal("device.example.com");
        identity.HasOtherSanEntries.Should().BeFalse();
    }

    [Fact]
    public void Extract_SpkiMatchesTheSigningKey()
    {
        using var key = NewKey();
        var csr = DeviceCsrBuilder.Build(key, $"CN={Serial}");

        var identity = CsrHelper.ExtractCsrIdentity(csr);

        identity.SpkiDer.Should().Equal(key.ExportSubjectPublicKeyInfo());
    }

    [Fact]
    public void Extract_BareUtf8OtherName_IsFlaggedNotParsed()
    {
        // A PermanentIdentifier encoded without the RFC 4043 SEQUENCE (the
        // value sits directly under [0] EXPLICIT) is not the canonical form:
        // it must flag the CSR, never pass as a parsed identifier.
        using var key = NewKey();
        var csr = BuildCsrWithRawSan(key, writer =>
        {
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                writer.WriteObjectIdentifier(DeviceCsrBuilder.IdOnPermanentIdentifier);
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                    writer.WriteCharacterString(UniversalTagNumber.UTF8String, Serial);
            }
        });

        var identity = CsrHelper.ExtractCsrIdentity(csr);

        identity.PermanentIdentifiers.Should().BeEmpty();
        identity.HasOtherSanEntries.Should().BeTrue();
    }

    [Fact]
    public void Extract_OtherNameWithDifferentTypeId_IsFlagged()
    {
        // A UPN otherName (or any non PermanentIdentifier type) is content
        // the attestation never vouched for.
        using var key = NewKey();
        var csr = BuildCsrWithRawSan(key, writer =>
        {
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                writer.WriteObjectIdentifier("1.3.6.1.4.1.311.20.2.3");
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                    writer.WriteCharacterString(
                        UniversalTagNumber.UTF8String, "user@example.com");
            }
        });

        var identity = CsrHelper.ExtractCsrIdentity(csr);

        identity.PermanentIdentifiers.Should().BeEmpty();
        identity.HasOtherSanEntries.Should().BeTrue();
    }

    [Fact]
    public void Extract_AssignerOnlyPermanentIdentifier_IsFlagged()
    {
        // RFC 4043 allows a PermanentIdentifier with no identifierValue, but
        // there is nothing to compare an order identifier against, so it is
        // treated as unrecognized content.
        using var key = NewKey();
        var csr = BuildCsrWithRawSan(key, writer =>
        {
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                writer.WriteObjectIdentifier(DeviceCsrBuilder.IdOnPermanentIdentifier);
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                using (writer.PushSequence())
                    writer.WriteObjectIdentifier(Assigner);
            }
        });

        var identity = CsrHelper.ExtractCsrIdentity(csr);

        identity.PermanentIdentifiers.Should().BeEmpty();
        identity.HasOtherSanEntries.Should().BeTrue();
    }

    [Fact]
    public void Extract_Rfc822Name_IsFlagged()
    {
        using var key = NewKey();
        var csr = BuildCsrWithRawSan(key, writer =>
            writer.WriteCharacterString(
                UniversalTagNumber.IA5String, "device@example.com",
                new Asn1Tag(TagClass.ContextSpecific, 1)));

        var identity = CsrHelper.ExtractCsrIdentity(csr);

        identity.HasOtherSanEntries.Should().BeTrue();
    }

    // ── Attribute carriers and requested extensions (issue #548) ────────

    [Fact]
    public void Extract_SanUnderCertExtensions_FlagsUnexpectedAttribute()
    {
        // The lab Run 1 shape: a SAN under szOID_CERT_EXTENSIONS, a carrier the
        // SAN walk never reads, so the name does not even surface, which is
        // exactly why the attribute itself must be refused.
        var csr = CarrierCsrBuilder.SanUnderCertExtensions("cn.example.com", "smuggled.example.com");

        var identity = CsrHelper.ExtractCsrIdentity(csr);

        identity.HasUnexpectedCsrAttributes.Should().BeTrue();
        identity.DnsNames.Should().BeEmpty();
    }

    [Fact]
    public void Extract_SanViaNameValuePair_FlagsUnexpectedAttribute()
    {
        var csr = CarrierCsrBuilder.SanViaNameValuePair("cn.example.com", "SAN", "dns=smuggled.example.com");

        var identity = CsrHelper.ExtractCsrIdentity(csr);

        identity.HasUnexpectedCsrAttributes.Should().BeTrue();
    }

    [Fact]
    public void Extract_SecondExtensionRequestValue_FlagsUnexpectedAttribute()
    {
        // The product reads only value[0], so the first name surfaces and the
        // second is invisible; the count mismatch is what refuses the CSR.
        var csr = CarrierCsrBuilder.SecondExtensionRequestValue(
            "cn.example.com", "first.example.com", "smuggled.example.com");

        var identity = CsrHelper.ExtractCsrIdentity(csr);

        identity.HasUnexpectedCsrAttributes.Should().BeTrue();
        identity.DnsNames.Should().Contain("first.example.com");
        identity.DnsNames.Should().NotContain("smuggled.example.com");
    }

    [Fact]
    public void Extract_TwoExtensionRequestAttributes_FlagsUnexpectedAttribute()
    {
        var csr = CarrierCsrBuilder.TwoExtensionRequestAttributes(
            "cn.example.com", "first.example.com", "smuggled.example.com");

        var identity = CsrHelper.ExtractCsrIdentity(csr);

        identity.HasUnexpectedCsrAttributes.Should().BeTrue();
    }

    [Fact]
    public void Extract_RequestedApplicationPolicies_FlagsDisallowedExtension()
    {
        // The lab Run 4 shape: a SAN plus a requested Application Policies
        // extension, which ADCS can copy into the certificate (ESC15).
        var csr = CarrierCsrBuilder.SanPlusRequestedExtension(
            "cn.example.com", "cn.example.com",
            CarrierCsrBuilder.ApplicationPoliciesExtension("1.3.6.1.4.1.311.20.2.2"));

        var identity = CsrHelper.ExtractCsrIdentity(csr);

        identity.HasUnexpectedCsrAttributes.Should().BeFalse();
        identity.DisallowedRequestedExtensionOid.Should().Be(CarrierCsrBuilder.ApplicationPoliciesOid);
    }

    // ── Basic constraints and the subject key identifier (issue #687) ────

    [Fact]
    public void Extract_RequestedCaCertificate_IsRefusedAndSaysSo()
    {
        // The guard #548 exists for: a requester must never obtain a CA
        // certificate. Admitting cA=false must not admit this.
        var csr = CarrierCsrBuilder.SanPlusRequestedExtension(
            "cn.example.com", "cn.example.com",
            CarrierCsrBuilder.BasicConstraintsExtension(isCa: true));

        var identity = CsrHelper.ExtractCsrIdentity(csr);

        identity.DisallowedRequestedExtensionOid.Should().Be("2.5.29.19");
        identity.DisallowedRequestedExtensionDetail.Should().Contain("cA=true");
    }

    [Fact]
    public void Extract_RequestedCaCertificateMarkedCritical_IsRefused()
    {
        var csr = CarrierCsrBuilder.SanPlusRequestedExtension(
            "cn.example.com", "cn.example.com",
            CarrierCsrBuilder.BasicConstraintsExtension(isCa: true, pathLen: 0, critical: true));

        var identity = CsrHelper.ExtractCsrIdentity(csr);

        identity.DisallowedRequestedExtensionOid.Should().Be("2.5.29.19");
        identity.DisallowedRequestedExtensionDetail.Should().Contain("cA=true");
    }

    [Fact]
    public void Extract_RequestedPathLengthWithoutCa_IsRefused()
    {
        // RFC 5280 allows a path length only with cA=true, so a request for one
        // is not an end entity request, whatever its cA says.
        var csr = CarrierCsrBuilder.SanPlusRequestedExtension(
            "cn.example.com", "cn.example.com",
            CarrierCsrBuilder.BasicConstraintsExtension(isCa: false, pathLen: 3));

        var identity = CsrHelper.ExtractCsrIdentity(csr);

        identity.DisallowedRequestedExtensionOid.Should().Be("2.5.29.19");
        identity.DisallowedRequestedExtensionDetail.Should().Contain("path length");
    }

    [Fact]
    public void Extract_RepeatedBasicConstraints_DoesNotParse()
    {
        // A cA=false the value check admits, then a cA=true a CA might honour.
        // BouncyCastle refuses a repeated extension outright, and both finalize
        // paths answer a CSR that does not parse with badCSR.
        var csr = CarrierCsrBuilder.SanPlusRequestedExtension(
            "cn.example.com", "cn.example.com",
            CarrierCsrBuilder.BasicConstraintsExtension(isCa: false),
            CarrierCsrBuilder.BasicConstraintsExtension(isCa: true));

        var act = () => CsrHelper.ExtractCsrIdentity(csr);

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Extract_BasicConstraintsWithAnUnknownElement_IsRefused()
    {
        var csr = CarrierCsrBuilder.SanPlusRequestedExtension(
            "cn.example.com", "cn.example.com",
            CarrierCsrBuilder.BasicConstraintsExtension(isCa: false, trailingElement: true));

        var identity = CsrHelper.ExtractCsrIdentity(csr);

        identity.DisallowedRequestedExtensionOid.Should().Be("2.5.29.19");
        identity.DisallowedRequestedExtensionDetail.Should().Contain("does not decode");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Extract_RequestedEndEntityBasicConstraints_IsAllowed(bool critical)
    {
        // acme.sh sends basicConstraints = CA:FALSE beside OCSP must staple.
        var csr = CarrierCsrBuilder.SanPlusRequestedExtension(
            "cn.example.com", "cn.example.com",
            CarrierCsrBuilder.BasicConstraintsExtension(isCa: false, critical: critical));

        var identity = CsrHelper.ExtractCsrIdentity(csr);

        identity.DisallowedRequestedExtensionOid.Should().BeNull();
        identity.DisallowedRequestedExtensionDetail.Should().BeNull();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Extract_PoshAcmeCsr_IsAllowed(bool ecKey)
    {
        // The issue #687 regression: Posh-ACME requests basic constraints
        // (cA=false), key usage, the SANs and a subject key identifier on every
        // order, RSA or EC, and #548 refused the first of them.
        var csr = PoshAcmeCsrBuilder.Build(ecKey, ocspMustStaple: false, "test2.example.com", "www.example.com");

        var identity = CsrHelper.ExtractCsrIdentity(csr);

        identity.HasUnexpectedCsrAttributes.Should().BeFalse();
        identity.HasOtherSanEntries.Should().BeFalse();
        identity.DisallowedRequestedExtensionOid.Should().BeNull(identity.DisallowedRequestedExtensionDetail);
        identity.DnsNames.Should().Equal("test2.example.com", "www.example.com");
        identity.SubjectCns.Should().Equal("test2.example.com");
    }

    [Fact]
    public void Extract_PoshAcmeCsrWithMustStaple_IsRefusedForTheTlsFeature()
    {
        // OCSP must staple stays refused: the TLS feature is outside the allow
        // list, and the refusal names it rather than basic constraints.
        var csr = PoshAcmeCsrBuilder.Build(ecKey: false, ocspMustStaple: true, "test2.example.com");

        var identity = CsrHelper.ExtractCsrIdentity(csr);

        identity.DisallowedRequestedExtensionOid.Should().Be("1.3.6.1.5.5.7.1.24");
    }

    [Fact]
    public void Extract_SubjectKeyIdentifierOfTheCsrKey_IsAllowed()
    {
        var csr = CarrierCsrBuilder.SanPlusKeyDerivedExtension(
            "cn.example.com", "cn.example.com",
            subjectPublicKey => CarrierCsrBuilder.SubjectKeyIdentifierExtension(SHA1.HashData(subjectPublicKey)));

        var identity = CsrHelper.ExtractCsrIdentity(csr);

        identity.DisallowedRequestedExtensionOid.Should().BeNull(identity.DisallowedRequestedExtensionDetail);
    }

    [Fact]
    public void Extract_SubjectKeyIdentifierOfAnotherKey_IsRefused()
    {
        // A requester may name its own key only, never borrow an identifier
        // such as the issuing CA's.
        var borrowed = Convert.FromHexString("0123456789ABCDEF0123456789ABCDEF01234567");
        var csr = CarrierCsrBuilder.SanPlusRequestedExtension(
            "cn.example.com", "cn.example.com", CarrierCsrBuilder.SubjectKeyIdentifierExtension(borrowed));

        var identity = CsrHelper.ExtractCsrIdentity(csr);

        identity.DisallowedRequestedExtensionOid.Should().Be("2.5.29.14");
        identity.DisallowedRequestedExtensionDetail.Should().Contain("own public key");
    }

    [Fact]
    public void Extract_CriticalSubjectKeyIdentifier_IsRefused()
    {
        var csr = CarrierCsrBuilder.SanPlusKeyDerivedExtension(
            "cn.example.com", "cn.example.com",
            subjectPublicKey => CarrierCsrBuilder.SubjectKeyIdentifierExtension(
                SHA1.HashData(subjectPublicKey), critical: true));

        var identity = CsrHelper.ExtractCsrIdentity(csr);

        identity.DisallowedRequestedExtensionOid.Should().Be("2.5.29.14");
        identity.DisallowedRequestedExtensionDetail.Should().Contain("critical");
    }

    [Fact]
    public void Extract_RequestedKeyUsage_IsAllowed()
    {
        // cert-manager encodes key usage into the CSR by default, so a key
        // usage request must not be refused.
        var csr = CarrierCsrBuilder.SanPlusRequestedExtension(
            "cn.example.com", "cn.example.com", CarrierCsrBuilder.KeyUsageExtension());

        var identity = CsrHelper.ExtractCsrIdentity(csr);

        identity.HasUnexpectedCsrAttributes.Should().BeFalse();
        identity.DisallowedRequestedExtensionOid.Should().BeNull();
        identity.DnsNames.Should().Contain("cn.example.com");
    }

    [Fact]
    public void Extract_RequestedExtendedKeyUsage_IsAllowed()
    {
        var csr = CarrierCsrBuilder.SanPlusRequestedExtension(
            "cn.example.com", "cn.example.com", CarrierCsrBuilder.ExtendedKeyUsageExtension());

        var identity = CsrHelper.ExtractCsrIdentity(csr);

        identity.HasUnexpectedCsrAttributes.Should().BeFalse();
        identity.DisallowedRequestedExtensionOid.Should().BeNull();
    }

    [Fact]
    public void Extract_CleanSanOnly_FlagsNeither()
    {
        // Regression: an ordinary SAN only CSR carries neither flag.
        using var key = NewKey();
        var csr = DeviceCsrBuilder.Build(key, "CN=cn.example.com", null, null, "cn.example.com");

        var identity = CsrHelper.ExtractCsrIdentity(csr);

        identity.HasUnexpectedCsrAttributes.Should().BeFalse();
        identity.DisallowedRequestedExtensionOid.Should().BeNull();
    }

    [Fact]
    public void Extract_TamperedSignature_Throws()
    {
        using var key = NewKey();
        var csr = DeviceCsrBuilder.Build(key, $"CN={Serial}");
        csr[^1] ^= 0x01;

        var act = () => CsrHelper.ExtractCsrIdentity(csr);

        act.Should().Throw<Exception>();
    }

    [Fact]
    public void Extract_GarbageBytes_Throws()
    {
        var act = () => CsrHelper.ExtractCsrIdentity(new byte[] { 1, 2, 3 });

        act.Should().Throw<Exception>();
    }

    /// <summary>
    /// A signed CSR whose SAN extension content is written raw, for the
    /// malformation cases DeviceCsrBuilder deliberately cannot produce.
    /// </summary>
    private static byte[] BuildCsrWithRawSan(ECDsa key, Action<AsnWriter> writeGeneralNames)
    {
        var request = new CertificateRequest("O=Device Fleet", key, HashAlgorithmName.SHA256);
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
            writeGeneralNames(writer);
        request.CertificateExtensions.Add(
            new X509Extension("2.5.29.17", writer.Encode(), critical: false));
        return request.CreateSigningRequest();
    }
}

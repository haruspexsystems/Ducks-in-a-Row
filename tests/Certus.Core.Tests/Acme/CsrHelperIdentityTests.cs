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

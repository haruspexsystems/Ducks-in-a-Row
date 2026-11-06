using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certus.Core.Security;

namespace Certus.Core.Tests.Security;

/// <summary>
/// Tests for <see cref="IssuedNameCeiling.Evaluate"/>, the issued side of the
/// leaf guard: the names the CA actually put in the certificate, compared with
/// the order's dns identifiers. A non DNS SAN entry (the carrier smuggling
/// route's UPN otherName), a DNS name the order never asked for, and a subject
/// common name outside the order all refuse; a clean leaf passes.
/// </summary>
public class IssuedNameCeilingTests
{
    private const string UpnOtherNameOid = "1.3.6.1.4.1.311.20.2.3";

    private static ISet<string> Order(params string[] names) =>
        new HashSet<string>(names, StringComparer.Ordinal);

    [Fact]
    public void Evaluate_DnsSanMatchingOrder_Ok()
    {
        var der = SelfSigned("CN=a.example.com", san => san.AddDnsName("a.example.com"));

        var verdict = IssuedNameCeiling.Evaluate(der, Order("a.example.com"));

        verdict.Should().Be(CeilingVerdict.Ok);
    }

    [Fact]
    public void Evaluate_DnsSanNotInOrder_RefusesAsDnsMismatch()
    {
        // The smuggled dNSName shape: the CA put a name in the leaf the order
        // never authorized.
        var der = SelfSigned("CN=a.example.com", san =>
        {
            san.AddDnsName("a.example.com");
            san.AddDnsName("smuggled.example.com");
        });

        var verdict = IssuedNameCeiling.Evaluate(der, Order("a.example.com"));

        verdict.Allowed.Should().BeFalse();
        verdict.ReasonCode.Should().Be("name-dns-mismatch");
        verdict.Message.Should().Contain("smuggled.example.com");
    }

    [Fact]
    public void Evaluate_UpnOtherNameSan_RefusesAsNonDnsSan()
    {
        // The lab Run 1 shape reaching the leaf: a UPN otherName in the SAN,
        // which a dns order never authorizes and which the DNS and CN checks
        // would not otherwise see.
        var der = SelfSignedRawSan("CN=a.example.com", writer =>
        {
            writer.WriteCharacterString(
                UniversalTagNumber.IA5String, "a.example.com", new Asn1Tag(TagClass.ContextSpecific, 2));
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                writer.WriteObjectIdentifier(UpnOtherNameOid);
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                    writer.WriteCharacterString(UniversalTagNumber.UTF8String, "victim@example.com");
            }
        });

        var verdict = IssuedNameCeiling.Evaluate(der, Order("a.example.com"));

        verdict.Allowed.Should().BeFalse();
        verdict.ReasonCode.Should().Be("name-non-dns-san");
    }

    [Fact]
    public void Evaluate_CnNotInOrder_RefusesAsCnMismatch()
    {
        // SAN matches the order, so the SAN arm passes; the subject CN is the
        // one outside it.
        var der = SelfSigned("CN=evil.example.com", san => san.AddDnsName("a.example.com"));

        var verdict = IssuedNameCeiling.Evaluate(der, Order("a.example.com"));

        verdict.Allowed.Should().BeFalse();
        verdict.ReasonCode.Should().Be("name-cn-mismatch");
        verdict.Message.Should().Contain("evil.example.com");
    }

    [Fact]
    public void Evaluate_CnInOrderNoSan_Ok()
    {
        // The historical fallback: a leaf named only by its CN, which is one of
        // the order's identifiers.
        var der = SelfSigned("CN=a.example.com", san: null);

        var verdict = IssuedNameCeiling.Evaluate(der, Order("a.example.com"));

        verdict.Should().Be(CeilingVerdict.Ok);
    }

    [Fact]
    public void Evaluate_CaseInsensitiveMatch_Ok()
    {
        var der = SelfSigned("CN=A.Example.COM", san => san.AddDnsName("A.Example.COM"));

        var verdict = IssuedNameCeiling.Evaluate(der, Order("a.example.com"));

        verdict.Should().Be(CeilingVerdict.Ok);
    }

    [Fact]
    public void Evaluate_GarbageBytes_RefusesAsUnreadable()
    {
        var verdict = IssuedNameCeiling.Evaluate(new byte[] { 1, 2, 3 }, Order("a.example.com"));

        verdict.Allowed.Should().BeFalse();
        verdict.ReasonCode.Should().Be("name-unreadable");
    }

    private static byte[] SelfSigned(string subject, Action<SubjectAlternativeNameBuilder>? san)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
        if (san != null)
        {
            var builder = new SubjectAlternativeNameBuilder();
            san(builder);
            req.CertificateExtensions.Add(builder.Build());
        }
        using var cert = req.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));
        return cert.Export(X509ContentType.Cert);
    }

    private static byte[] SelfSignedRawSan(string subject, Action<AsnWriter> writeGeneralNames)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
            writeGeneralNames(writer);
        req.CertificateExtensions.Add(new X509Extension("2.5.29.17", writer.Encode(), critical: false));
        using var cert = req.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));
        return cert.Export(X509ContentType.Cert);
    }
}

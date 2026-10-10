using Certus.Core.Crl;

namespace Certus.Core.Tests.Crl;

/// <summary>
/// A CRL arrives over plain HTTP or out of the directory, so its signature is
/// the only thing tying it to the CA the chain says issued it.
/// </summary>
public class CrlSignatureVerifierTests
{
    private static readonly DateTimeOffset Published =
        new(2026, 9, 1, 10, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Verifies_a_crl_its_own_ca_signed()
    {
        using var ca = CrlTestPki.MintRootCa();
        var der = CrlTestPki.BuildCrl(ca, 1, Published, Published.AddDays(365));
        CrlHeaderReader.TryRead(der, out var header, out _).Should().BeTrue();

        CrlSignatureVerifier.Verify(header!, ca).Should().Be(CrlSignatureResult.Verified);
    }

    [Fact]
    public void Verifies_a_crl_an_elliptic_curve_ca_signed()
    {
        using var ca = CrlTestPki.MintEcdsaRootCa();
        var der = CrlTestPki.BuildCrl(ca, 1, Published, Published.AddDays(365));
        CrlHeaderReader.TryRead(der, out var header, out var error).Should().BeTrue(error);

        CrlSignatureVerifier.Verify(header!, ca).Should().Be(CrlSignatureResult.Verified);
    }

    [Fact]
    public void Refuses_a_crl_another_ca_signed()
    {
        using var ca = CrlTestPki.MintRootCa("CN=Contoso Root CA");
        using var impostor = CrlTestPki.MintRootCa("CN=Contoso Root CA");
        var der = CrlTestPki.BuildCrl(impostor, 1, Published, Published.AddDays(365));
        CrlHeaderReader.TryRead(der, out var header, out _).Should().BeTrue();

        // Same name, different key. Whatever can answer for a distribution point
        // could otherwise hold off an expiry warning by serving this.
        CrlSignatureVerifier.Verify(header!, ca).Should().Be(CrlSignatureResult.Failed);
    }

    [Fact]
    public void Reports_an_algorithm_it_does_not_implement_rather_than_a_failure()
    {
        using var ca = CrlTestPki.MintRootCa();
        var der = CrlTestPki.BuildCrl(
            ca, 1, Published, Published.AddDays(365),
            signatureAlgorithm: "SHA256WITHRSAANDMGF1");
        CrlHeaderReader.TryRead(der, out var header, out var error).Should().BeTrue(error);

        // RSASSA-PSS keeps its parameters in the algorithm identifier. Reporting
        // it as a failure would drop a legitimate CA out of monitoring, which is
        // the worse of the two mistakes available here.
        CrlSignatureVerifier.Verify(header!, ca)
            .Should().Be(CrlSignatureResult.AlgorithmNotSupported);
    }

    [Fact]
    public void Matches_the_issuer_by_encoded_bytes()
    {
        using var ca = CrlTestPki.MintRootCa("CN=Contoso Root CA, O=Contoso, C=NL");
        var der = CrlTestPki.BuildCrl(ca, 1, Published, Published.AddDays(365));
        CrlHeaderReader.TryRead(der, out var header, out _).Should().BeTrue();

        CrlSignatureVerifier.MatchesIssuer(header!, ca).Should().BeTrue();
    }

    [Fact]
    public void Does_not_match_a_different_issuer()
    {
        using var ca = CrlTestPki.MintRootCa("CN=Contoso Root CA");
        using var other = CrlTestPki.MintRootCa("CN=Fabrikam Root CA");
        var der = CrlTestPki.BuildCrl(other, 1, Published, Published.AddDays(365));
        CrlHeaderReader.TryRead(der, out var header, out _).Should().BeTrue();

        CrlSignatureVerifier.MatchesIssuer(header!, ca).Should().BeFalse();
    }

    [Fact]
    public void Refuses_a_crl_whose_signature_was_tampered_with()
    {
        using var ca = CrlTestPki.MintRootCa();
        var der = CrlTestPki.BuildCrl(ca, 1, Published, Published.AddDays(365));
        CrlHeaderReader.TryRead(der, out var header, out _).Should().BeTrue();

        var tampered = header! with
        {
            SignatureValue = Flip(header.SignatureValue.ToArray()),
        };

        CrlSignatureVerifier.Verify(tampered, ca).Should().Be(CrlSignatureResult.Failed);
    }

    [Fact]
    public void Refuses_a_crl_whose_body_was_tampered_with()
    {
        using var ca = CrlTestPki.MintRootCa();
        var der = CrlTestPki.BuildCrl(ca, 1, Published, Published.AddDays(365));
        CrlHeaderReader.TryRead(der, out var header, out _).Should().BeTrue();

        var tampered = header! with
        {
            TbsBytes = Flip(header.TbsBytes.ToArray()),
        };

        // A nextUpdate edited on the wire is exactly the attack this check is
        // for, and the signature covers these bytes.
        CrlSignatureVerifier.Verify(tampered, ca).Should().Be(CrlSignatureResult.Failed);
    }

    private static byte[] Flip(byte[] value)
    {
        value[^1] ^= 0xFF;
        return value;
    }
}

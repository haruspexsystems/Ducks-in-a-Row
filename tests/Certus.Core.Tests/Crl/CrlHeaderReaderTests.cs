using System.Text;
using Certus.Core.Crl;

namespace Certus.Core.Tests.Crl;

/// <summary>
/// The reader is the product's only route to a CRL's dates, because .NET has no
/// CRL reader and BouncyCastle's would decode every revocation entry.
/// </summary>
public class CrlHeaderReaderTests
{
    private static readonly DateTimeOffset Published =
        new(2026, 9, 1, 10, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Reads_the_dates_the_number_and_the_key_identifier()
    {
        using var ca = CrlTestPki.MintRootCa();
        var der = CrlTestPki.BuildCrl(ca, 12, Published, Published.AddDays(365));

        CrlHeaderReader.TryRead(der, out var header, out var error).Should().BeTrue(error);
        header!.ThisUpdate.Should().BeCloseTo(Published, TimeSpan.FromSeconds(1));
        header.NextUpdate.Should().NotBeNull();
        header.NextUpdate!.Value.Should().BeCloseTo(Published.AddDays(365), TimeSpan.FromSeconds(1));
        header.CrlNumberHex.Should().Be("0C");
        header.AuthorityKeyIdentifierHex.Should().NotBeNullOrEmpty();
        header.IsDelta.Should().BeFalse();
        header.SignatureAlgorithmOid.Should().Be("1.2.840.113549.1.1.11");
    }

    [Fact]
    public void Carries_the_issuer_name_as_encoded_bytes()
    {
        using var ca = CrlTestPki.MintRootCa("CN=Contoso Root CA, O=Contoso, C=NL");
        var der = CrlTestPki.BuildCrl(ca, 1, Published, Published.AddDays(30));

        CrlHeaderReader.TryRead(der, out var header, out _).Should().BeTrue();

        // Bytes, not the rendered string: a distinguished name renders in the
        // reverse of the order it encodes in, so this is the comparison that
        // says the CRL really was issued by this certificate's subject.
        header!.IssuerNameDer.ToArray().Should().Equal(ca.SubjectName.RawData);
        header.IssuerName.Should().Contain("Contoso Root CA");
    }

    [Fact]
    public void Reads_the_microsoft_next_publish_extension()
    {
        using var ca = CrlTestPki.MintRootCa();
        var nextPublish = Published.AddDays(364);
        var der = CrlTestPki.BuildCrl(ca, 3, Published, Published.AddDays(365), nextPublish);

        CrlHeaderReader.TryRead(der, out var header, out _).Should().BeTrue();

        header!.NextPublish.Should().NotBeNull();
        header.NextPublish!.Value.Should().BeCloseTo(nextPublish, TimeSpan.FromSeconds(1));
    }

    [Fact]
    public void Reports_no_next_publish_when_the_extension_is_absent()
    {
        using var ca = CrlTestPki.MintRootCa();
        var der = CrlTestPki.BuildCrl(ca, 3, Published, Published.AddDays(365));

        CrlHeaderReader.TryRead(der, out var header, out _).Should().BeTrue();

        header!.NextPublish.Should().BeNull();
    }

    [Fact]
    public void Recognises_a_delta_crl_by_its_indicator()
    {
        using var ca = CrlTestPki.MintRootCa();
        var der = CrlTestPki.BuildCrl(
            ca, 14, Published, Published.AddDays(1), baseCrlNumber: 12);

        CrlHeaderReader.TryRead(der, out var header, out _).Should().BeTrue();

        header!.IsDelta.Should().BeTrue();
        header.BaseCrlNumberHex.Should().Be("0C");
        header.CrlNumberHex.Should().Be("0E");
    }

    [Fact]
    public void Trims_the_sign_pad_byte_off_a_crl_number()
    {
        using var ca = CrlTestPki.MintRootCa();
        // 255 encodes as 00 FF, the leading byte being the sign pad. Two
        // renderings of one number must not compare unequal, because the number
        // is half of the identity the alert history dedupes on.
        var der = CrlTestPki.BuildCrl(ca, 255, Published, Published.AddDays(30));

        CrlHeaderReader.TryRead(der, out var header, out _).Should().BeTrue();

        header!.CrlNumberHex.Should().Be("FF");
    }

    [Fact]
    public void Reads_a_crl_padded_with_revocation_entries_without_decoding_them()
    {
        using var ca = CrlTestPki.MintRootCa();
        var der = CrlTestPki.BuildCrl(
            ca, 7, Published, Published.AddDays(7), revokedEntries: 2000);

        CrlHeaderReader.TryRead(der, out var header, out var error).Should().BeTrue(error);

        header!.CrlNumberHex.Should().Be("07");
        header.NextUpdate!.Value.Should().BeCloseTo(Published.AddDays(7), TimeSpan.FromSeconds(1));
    }

    [Fact]
    public void Accepts_a_crl_with_no_next_update()
    {
        using var ca = CrlTestPki.MintRootCa();
        var der = CrlTestPki.BuildCrl(ca, 2, Published, nextUpdate: null);

        CrlHeaderReader.TryRead(der, out var header, out var error).Should().BeTrue(error);

        header!.NextUpdate.Should().BeNull();
        header.ThisUpdate.Should().BeCloseTo(Published, TimeSpan.FromSeconds(1));
    }

    [Fact]
    public void Accepts_a_crl_with_no_crl_number()
    {
        using var ca = CrlTestPki.MintRootCa();
        var der = CrlTestPki.BuildCrl(
            ca, 0, Published, Published.AddDays(30), includeCrlNumber: false);

        CrlHeaderReader.TryRead(der, out var header, out _).Should().BeTrue();

        header!.CrlNumberHex.Should().BeNull();
        header.NextUpdate.Should().NotBeNull();
    }

    [Fact]
    public void Refuses_bytes_that_are_not_a_crl()
    {
        var garbage = Encoding.ASCII.GetBytes("<html>404 not found</html>");

        CrlHeaderReader.TryRead(garbage, out var header, out var error).Should().BeFalse();

        header.Should().BeNull();
        error.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void Refuses_an_empty_body()
    {
        CrlHeaderReader.TryRead(ReadOnlyMemory<byte>.Empty, out var header, out var error)
            .Should().BeFalse();

        header.Should().BeNull();
        error.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void Refuses_a_certificate_offered_as_a_crl()
    {
        using var ca = CrlTestPki.MintRootCa();

        // A distribution point serving the wrong file is a real misconfiguration,
        // and a certificate is shaped enough like a CRL to be worth pinning.
        CrlHeaderReader.TryRead(ca.RawData, out var header, out var error).Should().BeFalse();

        header.Should().BeNull();
        error.Should().NotBeNullOrEmpty();
    }
}

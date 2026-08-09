using System.Formats.Cbor;
using System.Security.Cryptography.X509Certificates;
using Certus.Core.Acme.Attestation;

namespace Certus.Core.Tests.Acme.Attestation;

/// <summary>
/// Tests for the apple format verifier against synthetic chains carrying
/// the real Apple OIDs. The load bearing checks: the chain must reach a
/// trust anchor, the nonce must be SHA-256 of the raw token bytes, and the
/// order identifier must octet match the attested serial or UDID.
/// </summary>
public class AppleAttestationVerifierTests : IDisposable
{
    private const string Token = "tok-device-abc123";
    private const string Serial = "SYN-SN-0001";
    private const string Udid = "00008030-000A1B2C3D4E5F60";

    private readonly X509Certificate2 _root = SyntheticAttestationBuilder.CreateRoot();
    private readonly AppleAttestationVerifier _sut = new();

    private AttestationContext Context(
        byte[] attestationObject, string expectedIdentifier, params X509Certificate2[] anchors) =>
        new(AttestationEnvelope.Parse(attestationObject),
            Token,
            expectedIdentifier,
            anchors.Length > 0 ? anchors : new[] { _root });

    private X509Certificate2 GenuineLeaf() =>
        SyntheticAttestationBuilder.CreateLeaf(
            _root, Serial, Udid, SyntheticAttestationBuilder.NonceFor(Token), sepOsVersion: "26.0");

    [Fact]
    public void Format_IsApple()
    {
        _sut.Format.Should().Be("apple");
    }

    [Fact]
    public void Constructor_EmbeddedRootPassesPinCheck()
    {
        // Constructing the verifier loads the embedded Apple root and checks it
        // against the pinned SHA-256; a mispackaged resource would throw here.
        var act = () => new AppleAttestationVerifier();

        act.Should().NotThrow();
    }

    [Fact]
    public async Task Verify_SerialMatch_Succeeds()
    {
        using var leaf = GenuineLeaf();
        var attObj = SyntheticAttestationBuilder.BuildAttestationObject("apple", new[] { leaf });

        var result = await _sut.VerifyAsync(Context(attObj, Serial));

        result.IsValid.Should().BeTrue(result.ErrorDetail);
        result.AttestedIdentifierValue.Should().Be(Serial);
        result.AttestedSpkiDer.Should().Equal(leaf.PublicKey.ExportSubjectPublicKeyInfo());
        result.AttestedProperties.Should().Contain("serialNumber", Serial);
        result.AttestedProperties.Should().Contain("udid", Udid);
        result.AttestedProperties.Should().Contain("sepOsVersion", "26.0");
    }

    [Fact]
    public async Task Verify_UdidMatch_Succeeds()
    {
        // MDM operators use either the serial or the UDID as the
        // ClientIdentifier; both must be accepted.
        using var leaf = GenuineLeaf();
        var attObj = SyntheticAttestationBuilder.BuildAttestationObject("apple", new[] { leaf });

        var result = await _sut.VerifyAsync(Context(attObj, Udid));

        result.IsValid.Should().BeTrue(result.ErrorDetail);
        result.AttestedIdentifierValue.Should().Be(Udid);
    }

    [Fact]
    public async Task Verify_ChainThroughIntermediate_Succeeds()
    {
        // Real Apple chains run leaf, intermediate, root; the intermediate
        // arrives in x5c and only the root is an anchor.
        using var intermediate = SyntheticAttestationBuilder.CreateIntermediate(_root);
        using var leaf = SyntheticAttestationBuilder.CreateLeaf(
            intermediate, Serial, Udid, SyntheticAttestationBuilder.NonceFor(Token));
        var attObj = SyntheticAttestationBuilder.BuildAttestationObject(
            "apple", new[] { leaf, intermediate });

        var result = await _sut.VerifyAsync(Context(attObj, Serial));

        result.IsValid.Should().BeTrue(result.ErrorDetail);
    }

    [Fact]
    public async Task Verify_WrongNonce_Fails()
    {
        using var leaf = SyntheticAttestationBuilder.CreateLeaf(
            _root, Serial, Udid, SyntheticAttestationBuilder.NonceFor("a-different-token"));
        var attObj = SyntheticAttestationBuilder.BuildAttestationObject("apple", new[] { leaf });

        var result = await _sut.VerifyAsync(Context(attObj, Serial));

        result.IsValid.Should().BeFalse();
        result.ErrorDetail.Should().Contain("nonce");
    }

    [Fact]
    public async Task Verify_MissingNonce_Fails()
    {
        using var leaf = SyntheticAttestationBuilder.CreateLeaf(_root, Serial, Udid, nonce: null);
        var attObj = SyntheticAttestationBuilder.BuildAttestationObject("apple", new[] { leaf });

        var result = await _sut.VerifyAsync(Context(attObj, Serial));

        result.IsValid.Should().BeFalse();
        result.ErrorDetail.Should().Contain("nonce");
    }

    [Fact]
    public async Task Verify_UntrustedChain_Fails()
    {
        using var leaf = GenuineLeaf();
        using var otherRoot = SyntheticAttestationBuilder.CreateRoot("CN=Some Other Root");
        var attObj = SyntheticAttestationBuilder.BuildAttestationObject("apple", new[] { leaf });

        var result = await _sut.VerifyAsync(Context(attObj, Serial, otherRoot));

        result.IsValid.Should().BeFalse();
        result.ErrorDetail.Should().Contain("not trusted");
    }

    [Fact]
    public async Task Verify_ExpiredLeaf_Fails()
    {
        using var leaf = SyntheticAttestationBuilder.CreateLeaf(
            _root, Serial, Udid, SyntheticAttestationBuilder.NonceFor(Token),
            notBefore: DateTimeOffset.UtcNow.AddDays(-10),
            notAfter: DateTimeOffset.UtcNow.AddDays(-1));
        var attObj = SyntheticAttestationBuilder.BuildAttestationObject("apple", new[] { leaf });

        var result = await _sut.VerifyAsync(Context(attObj, Serial));

        result.IsValid.Should().BeFalse();
        result.ErrorDetail.Should().Contain("not trusted");
    }

    [Fact]
    public async Task Verify_IdentifierMismatch_Fails()
    {
        using var leaf = GenuineLeaf();
        var attObj = SyntheticAttestationBuilder.BuildAttestationObject("apple", new[] { leaf });

        var result = await _sut.VerifyAsync(Context(attObj, "SOME-OTHER-DEVICE"));

        result.IsValid.Should().BeFalse();
        result.ErrorDetail.Should().Contain("identifiers do not match");
    }

    [Fact]
    public async Task Verify_AssignerQualifiedIdentifier_NeverMatches()
    {
        // The draft compares octet for octet. Apple devices attest bare serial
        // and UDID strings, so "value/assigner-OID" can never match an apple
        // attestation, even when the value half matches the serial.
        using var leaf = GenuineLeaf();
        var attObj = SyntheticAttestationBuilder.BuildAttestationObject("apple", new[] { leaf });

        var result = await _sut.VerifyAsync(Context(attObj, $"{Serial}/1.3.6.1.4.1.99999.1"));

        result.IsValid.Should().BeFalse();
        result.ErrorDetail.Should().Contain("identifiers do not match");
    }

    [Fact]
    public async Task Verify_MissingX5c_Fails()
    {
        var writer = new CborWriter(CborConformanceMode.Lax);
        writer.WriteStartMap(2);
        writer.WriteTextString("fmt");
        writer.WriteTextString("apple");
        writer.WriteTextString("attStmt");
        writer.WriteStartMap(0);
        writer.WriteEndMap();
        writer.WriteEndMap();

        var result = await _sut.VerifyAsync(Context(writer.Encode(), Serial));

        result.IsValid.Should().BeFalse();
        result.ErrorDetail.Should().Contain("no certificate chain");
    }

    public void Dispose()
    {
        _root.Dispose();
    }
}

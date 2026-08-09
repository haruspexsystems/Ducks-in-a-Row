using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Certus.Core.Acme.Attestation;
using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Models;
using Certus.Core.Acme.Services;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;

namespace Certus.Core.Tests.Acme.Attestation;

/// <summary>
/// Tests for the device-attest-01 validator over the real verifier, anchor
/// store, and policy service (in memory SQLite). The load bearing
/// properties: every failure is final with the badAttestationStatement
/// error type, and the device gate is re-checked mid flight so a profile
/// disabled or a device delisted after newOrder still refuses.
/// </summary>
public class DeviceAttest01ChallengeValidatorTests : IDisposable
{
    private const string Template = "DeviceAuth";
    private const string Serial = "SYN-SN-0001";
    private const string Udid = "UDID-0001";
    private const string Token = "tok-device-abc123";

    private readonly SqliteConnection _connection;
    private readonly CertusDbContext _db;
    private readonly X509Certificate2 _root;
    private readonly X509Certificate2 _leaf;
    private readonly DeviceAttest01ChallengeValidator _sut;

    public DeviceAttest01ChallengeValidatorTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();

        var options = new DbContextOptionsBuilder<CertusDbContext>()
            .UseSqlite(_connection)
            .Options;
        _db = new CertusDbContext(options);
        _db.Database.EnsureCreated();

        _root = SyntheticAttestationBuilder.CreateRoot();
        _leaf = SyntheticAttestationBuilder.CreateLeaf(
            _root, Serial, Udid, SyntheticAttestationBuilder.NonceFor(Token));

        _sut = new DeviceAttest01ChallengeValidator(
            new IAttestationFormatVerifier[] { new AppleAttestationVerifier() },
            new AttestationTrustAnchorStore(_db, NullLogger<AttestationTrustAnchorStore>.Instance),
            new DeviceAttestationPolicyService(_db),
            NullLogger<DeviceAttest01ChallengeValidator>.Instance);
    }

    private void SeedAnchor(bool enabled = true)
    {
        _db.AttestationTrustAnchors.Add(new AttestationTrustAnchor
        {
            Format = "apple",
            Name = "synthetic root",
            CertificatePem = SyntheticAttestationBuilder.ToPem(_root),
            Sha256Fingerprint = Convert.ToHexString(SHA256.HashData(_root.RawData)).ToLowerInvariant(),
            Enabled = enabled
        });
        _db.SaveChanges();
        _db.ChangeTracker.Clear();
    }

    private void SeedProfile(
        bool enabled = true,
        string gateMode = DeviceAttestationGateModes.Allowlist,
        params string[] devices)
    {
        var profile = new DeviceAttestationProfile
        {
            TemplateId = Template,
            Enabled = enabled,
            GateMode = gateMode
        };
        foreach (var device in devices)
            profile.AllowlistEntries.Add(new DeviceAllowlistEntry { IdentifierValue = device });
        _db.DeviceAttestationProfiles.Add(profile);
        _db.SaveChanges();
        _db.ChangeTracker.Clear();
    }

    private string Payload(params X509Certificate2[] chain) =>
        SyntheticAttestationBuilder.ToChallengePayload(
            SyntheticAttestationBuilder.BuildAttestationObject(
                "apple", chain.Length > 0 ? chain : new[] { _leaf }));

    private static ChallengeValidationContext Context(
        string? payload,
        string identifier = Serial,
        string identifierType = "permanent-identifier") =>
        new(identifierType, identifier, Token, "thumb-device", Template, payload);

    [Fact]
    public void ChallengeType_IsDeviceAttest01()
    {
        _sut.ChallengeType.Should().Be("device-attest-01");
        DeviceAttest01ChallengeValidator.TypeName.Should().Be("device-attest-01");
    }

    [Fact]
    public async Task Validate_MissingPayload_FailsFinal()
    {
        var result = await _sut.ValidateAsync(Context(payload: null));

        result.IsValid.Should().BeFalse();
        result.Transient.Should().BeFalse("a missing attestation stays missing on retry");
        result.ErrorType.Should().Be(AcmeErrorType.BadAttestationStatement);
        result.ErrorDetail.Should().Contain("attestation object");
    }

    [Fact]
    public async Task Validate_PayloadNotBase64Url_Fails()
    {
        var result = await _sut.ValidateAsync(Context("%%%not-base64url%%%"));

        result.IsValid.Should().BeFalse();
        result.ErrorType.Should().Be(AcmeErrorType.BadAttestationStatement);
        result.ErrorDetail.Should().Contain("base64url");
    }

    [Fact]
    public async Task Validate_PayloadNotCbor_Fails()
    {
        var payload = JwsService.Base64UrlEncode(Encoding.ASCII.GetBytes("not cbor"));

        var result = await _sut.ValidateAsync(Context(payload));

        result.IsValid.Should().BeFalse();
        result.ErrorType.Should().Be(AcmeErrorType.BadAttestationStatement);
    }

    [Fact]
    public async Task Validate_UnknownFormat_Fails()
    {
        var payload = SyntheticAttestationBuilder.ToChallengePayload(
            SyntheticAttestationBuilder.BuildAttestationObject("tpm", new[] { _leaf }));

        var result = await _sut.ValidateAsync(Context(payload));

        result.IsValid.Should().BeFalse();
        result.ErrorDetail.Should().Contain("tpm");
    }

    [Fact]
    public async Task Validate_WrongIdentifierType_Fails()
    {
        var result = await _sut.ValidateAsync(Context(Payload(), identifierType: "dns"));

        result.IsValid.Should().BeFalse();
        result.ErrorDetail.Should().Contain("dns");
    }

    [Fact]
    public async Task Validate_OpenProfile_Succeeds()
    {
        SeedAnchor();
        SeedProfile(gateMode: DeviceAttestationGateModes.Open);

        var result = await _sut.ValidateAsync(Context(Payload()));

        result.IsValid.Should().BeTrue(result.ErrorDetail);
        result.ErrorType.Should().BeNull();
        result.Attested.Should().NotBeNull();
        result.Attested!.Format.Should().Be("apple");
        result.Attested.SpkiBase64.Should().Be(
            Convert.ToBase64String(_leaf.PublicKey.ExportSubjectPublicKeyInfo()));
        result.Attested.PropertiesJson.Should().Contain(Serial).And.Contain(Udid);
    }

    [Fact]
    public async Task Validate_ListedDevice_Succeeds()
    {
        SeedAnchor();
        SeedProfile(devices: Serial);

        var result = await _sut.ValidateAsync(Context(Payload()));

        result.IsValid.Should().BeTrue(result.ErrorDetail);
    }

    [Fact]
    public async Task Validate_NoAnchor_ChainNotTrusted()
    {
        // Without the synthetic anchor row only the embedded Apple root
        // anchors the chain, and it must refuse a synthetic chain.
        SeedProfile(gateMode: DeviceAttestationGateModes.Open);

        var result = await _sut.ValidateAsync(Context(Payload()));

        result.IsValid.Should().BeFalse();
        result.ErrorDetail.Should().Contain("not trusted");
    }

    [Fact]
    public async Task Validate_DisabledAnchor_IsNotUsed()
    {
        SeedAnchor(enabled: false);
        SeedProfile(gateMode: DeviceAttestationGateModes.Open);

        var result = await _sut.ValidateAsync(Context(Payload()));

        result.IsValid.Should().BeFalse();
        result.ErrorDetail.Should().Contain("not trusted");
    }

    [Fact]
    public async Task Validate_MalformedAnchorRow_IsSkipped()
    {
        // A corrupt anchor row must not take down the format; the healthy
        // anchor still verifies the chain.
        _db.AttestationTrustAnchors.Add(new AttestationTrustAnchor
        {
            Format = "apple",
            Name = "corrupt anchor",
            CertificatePem = "not a pem",
            Sha256Fingerprint = new string('b', 64),
            Enabled = true
        });
        _db.SaveChanges();
        _db.ChangeTracker.Clear();
        SeedAnchor();
        SeedProfile(gateMode: DeviceAttestationGateModes.Open);

        var result = await _sut.ValidateAsync(Context(Payload()));

        result.IsValid.Should().BeTrue(result.ErrorDetail);
    }

    [Fact]
    public async Task Validate_NoProfile_FailsClosedMidFlight()
    {
        // The attestation itself is perfect; the gate alone must refuse when
        // the profile disappeared between newOrder and this sweep.
        SeedAnchor();

        var result = await _sut.ValidateAsync(Context(Payload()));

        result.IsValid.Should().BeFalse();
        result.ErrorType.Should().Be(AcmeErrorType.BadAttestationStatement);
        result.ErrorDetail.Should().Contain("policy");
    }

    [Fact]
    public async Task Validate_DisabledProfile_FailsClosedMidFlight()
    {
        SeedAnchor();
        SeedProfile(enabled: false, devices: Serial);

        var result = await _sut.ValidateAsync(Context(Payload()));

        result.IsValid.Should().BeFalse();
        result.ErrorDetail.Should().Contain("policy");
    }

    [Fact]
    public async Task Validate_UnlistedDevice_FailsClosedMidFlight()
    {
        SeedAnchor();
        SeedProfile(devices: "SOME-OTHER-SN");

        var result = await _sut.ValidateAsync(Context(Payload()));

        result.IsValid.Should().BeFalse();
        result.ErrorDetail.Should().Contain("policy");
    }

    [Fact]
    public async Task Validate_WrongNonce_CarriesVerifierDetail()
    {
        SeedAnchor();
        SeedProfile(gateMode: DeviceAttestationGateModes.Open);
        using var wrongLeaf = SyntheticAttestationBuilder.CreateLeaf(
            _root, Serial, Udid, SyntheticAttestationBuilder.NonceFor("a-different-token"));

        var result = await _sut.ValidateAsync(Context(Payload(wrongLeaf)));

        result.IsValid.Should().BeFalse();
        result.ErrorType.Should().Be(AcmeErrorType.BadAttestationStatement);
        result.ErrorDetail.Should().Contain("nonce");
    }

    public void Dispose()
    {
        _db.Dispose();
        _connection.Close();
        _connection.Dispose();
        _root.Dispose();
        _leaf.Dispose();
    }
}

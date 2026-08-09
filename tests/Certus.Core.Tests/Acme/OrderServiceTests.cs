using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certus.Core.Acme.Models;
using Certus.Core.Acme.Services;
using Certus.Core.Adcs;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Certus.Core.Services;
using Certus.Core.Tests.Acme.Attestation;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;

namespace Certus.Core.Tests.Acme;

public class OrderServiceTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly CertusDbContext _db;
    private readonly OrderService _sut;
    private readonly MockAdcsClient _adcsClient;
    private readonly CertificateSyncTrigger _syncTrigger;
    private readonly AcmeAccount _account;
    private readonly List<ECDsa> _deviceKeys = new();

    public OrderServiceTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();

        var options = new DbContextOptionsBuilder<CertusDbContext>()
            .UseSqlite(_connection)
            .Options;
        _db = new CertusDbContext(options);
        _db.Database.EnsureCreated();

        _adcsClient = new MockAdcsClient();
        _syncTrigger = new CertificateSyncTrigger();
        _sut = new OrderService(
            _db, _adcsClient, _syncTrigger,
            new DeviceAttestationPolicyService(_db),
            new DomainPolicyAuditService(_db, NullLogger<DomainPolicyAuditService>.Instance),
            NullLogger<OrderService>.Instance);

        // Seed a test account
        _account = new AcmeAccount
        {
            AccountId = "test-account-001",
            JwkJson = """{"kty":"RSA","n":"test","e":"AQAB"}""",
            JwkThumbprint = "test-thumbprint-001",
            Status = "valid",
            CreatedAt = DateTime.UtcNow
        };
        _db.AcmeAccounts.Add(_account);
        _db.SaveChanges();
    }

    [Fact]
    public async Task CreateOrder_ReturnsOrderWithPendingStatus()
    {
        var identifiers = new[] { new AcmeIdentifier { Type = "dns", Value = "example.com" } };

        var order = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);

        order.Should().NotBeNull();
        order.Status.Should().Be("pending");
        order.OrderId.Should().NotBeNullOrEmpty();
        order.TemplateId.Should().Be("WebServer");
    }

    [Fact]
    public async Task CreateOrder_CreatesAuthorizationPerIdentifier()
    {
        var identifiers = new[]
        {
            new AcmeIdentifier { Type = "dns", Value = "example.com" },
            new AcmeIdentifier { Type = "dns", Value = "www.example.com" }
        };

        var order = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);

        order.Authorizations.Should().HaveCount(2);
        order.Authorizations.Select(a => a.IdentifierValue)
            .Should().Contain("example.com")
            .And.Contain("www.example.com");
    }

    [Fact]
    public async Task CreateOrder_NonWildcard_CreatesAllThreeChallengeTypes()
    {
        var identifiers = new[] { new AcmeIdentifier { Type = "dns", Value = "example.com" } };

        var order = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);

        var authz = order.Authorizations.Single();
        authz.Challenges.Should().HaveCount(3);
        authz.Challenges.Select(c => c.Type).Should()
            .Contain("http-01")
            .And.Contain("dns-01")
            .And.Contain("tls-alpn-01");

        // RFC 8555 §8.1 models the token as per challenge, so each gets its own.
        authz.Challenges.Select(c => c.Token).Distinct().Should().HaveCount(3);
        authz.Challenges.Should().OnlyContain(c => c.Status == "pending");
    }

    [Fact]
    public async Task CreateOrder_WildcardIdentifier_OnlyGetsDns01()
    {
        var identifiers = new[] { new AcmeIdentifier { Type = "dns", Value = "*.example.com" } };

        var order = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);

        var authz = order.Authorizations.Single();
        authz.Wildcard.Should().BeTrue();
        authz.Challenges.Should().HaveCount(1);
        authz.Challenges[0].Type.Should().Be("dns-01");
    }

    [Fact]
    public async Task CreateOrder_SetsExpiresAt()
    {
        var identifiers = new[] { new AcmeIdentifier { Type = "dns", Value = "example.com" } };

        var order = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);

        order.ExpiresAt.Should().BeAfter(DateTime.UtcNow);
        order.ExpiresAt.Should().BeBefore(DateTime.UtcNow.AddDays(8));
    }

    [Fact]
    public async Task GetOrder_ReturnsOrderWithNavigationProperties()
    {
        var identifiers = new[] { new AcmeIdentifier { Type = "dns", Value = "example.com" } };
        var created = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);

        var fetched = await _sut.GetOrderAsync(created.OrderId);

        fetched.Should().NotBeNull();
        fetched!.OrderId.Should().Be(created.OrderId);
        fetched.Authorizations.Should().HaveCount(1);
        fetched.Authorizations[0].Challenges.Should().HaveCount(3); // http-01, dns-01, tls-alpn-01
    }

    [Fact]
    public async Task GetOrder_NonExistent_ReturnsNull()
    {
        var result = await _sut.GetOrderAsync("does-not-exist");
        result.Should().BeNull();
    }

    [Fact]
    public async Task RespondToChallenge_PendingChallenge_TransitionsToProcessing()
    {
        var identifiers = new[] { new AcmeIdentifier { Type = "dns", Value = "example.com" } };
        var order = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);
        var challengeId = order.Authorizations[0].Challenges[0].ChallengeId;

        var result = await _sut.RespondToChallengeAsync(challengeId);

        result.Should().BeTrue();

        var challenge = await _sut.GetChallengeAsync(challengeId);
        challenge!.Status.Should().Be("processing");
    }

    [Fact]
    public async Task RespondToChallenge_NonPending_ReturnsFalse()
    {
        var identifiers = new[] { new AcmeIdentifier { Type = "dns", Value = "example.com" } };
        var order = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);
        var challengeId = order.Authorizations[0].Challenges[0].ChallengeId;

        // First response succeeds
        await _sut.RespondToChallengeAsync(challengeId);
        // Second response fails (already processing)
        var result = await _sut.RespondToChallengeAsync(challengeId);

        result.Should().BeFalse();
    }

    [Fact]
    public async Task RecalculateOrderStatus_AllAuthzValid_OrderBecomesReady()
    {
        var identifiers = new[] { new AcmeIdentifier { Type = "dns", Value = "example.com" } };
        var order = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);

        // Manually set authorization to valid
        order.Authorizations[0].Status = "valid";
        await _db.SaveChangesAsync();

        await _sut.RecalculateOrderStatusAsync(order.Id);

        var updated = await _sut.GetOrderAsync(order.OrderId);
        updated!.Status.Should().Be("ready");
    }

    [Fact]
    public async Task RecalculateOrderStatus_AnyAuthzInvalid_OrderBecomesInvalid()
    {
        var identifiers = new[]
        {
            new AcmeIdentifier { Type = "dns", Value = "good.example.com" },
            new AcmeIdentifier { Type = "dns", Value = "bad.example.com" }
        };
        var order = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);

        order.Authorizations[0].Status = "valid";
        order.Authorizations[1].Status = "invalid";
        await _db.SaveChangesAsync();

        await _sut.RecalculateOrderStatusAsync(order.Id);

        var updated = await _sut.GetOrderAsync(order.OrderId);
        updated!.Status.Should().Be("invalid");
    }

    [Fact]
    public async Task FinalizeOrder_NotReady_Fails()
    {
        var identifiers = new[] { new AcmeIdentifier { Type = "dns", Value = "example.com" } };
        var order = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);

        var (success, _) = await _sut.FinalizeOrderAsync(order.OrderId, new byte[] { 1, 2, 3 });

        success.Should().BeFalse();
    }

    [Fact]
    public async Task ToResponse_IncludesCorrectUrls()
    {
        var identifiers = new[] { new AcmeIdentifier { Type = "dns", Value = "example.com" } };
        var order = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);

        var response = OrderService.ToResponse(order, path => $"https://certus{path}");

        response.Status.Should().Be("pending");
        response.Identifiers.Should().HaveCount(1);
        response.Identifiers[0].Value.Should().Be("example.com");
        response.Authorizations.Should().HaveCount(1);
        response.Authorizations[0].Should().Contain("/authz/");
        response.Finalize.Should().Contain($"/order/{order.OrderId}/finalize");
        response.Certificate.Should().BeNull(); // Not issued yet
    }

    [Fact]
    public async Task ToAuthorizationResponse_IncludesChallenges()
    {
        var identifiers = new[] { new AcmeIdentifier { Type = "dns", Value = "example.com" } };
        var order = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);
        var authz = order.Authorizations[0];

        var response = OrderService.ToAuthorizationResponse(
            authz, "WebServer", path => $"https://certus{path}");

        response.Identifier.Type.Should().Be("dns");
        response.Identifier.Value.Should().Be("example.com");
        response.Status.Should().Be("pending");
        response.Challenges.Should().HaveCount(3);
        response.Challenges.Select(c => c.Type).Should()
            .Contain("http-01")
            .And.Contain("dns-01")
            .And.Contain("tls-alpn-01");
        response.Challenges.Should().OnlyContain(c => c.Url.Contains("/chall/"));
        response.Challenges.Should().OnlyContain(c => !string.IsNullOrEmpty(c.Token));
    }

    [Fact]
    public async Task ToAuthorizationResponse_WildcardIdentifier_StripsPrefixAndSetsWildcard()
    {
        // RFC 8555 §7.1.4: the authorization identifier carries the base domain
        // without the "*." prefix; the wildcard field signals the wildcard.
        var identifiers = new[] { new AcmeIdentifier { Type = "dns", Value = "*.example.com" } };
        var order = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);
        var authz = order.Authorizations[0];

        var response = OrderService.ToAuthorizationResponse(
            authz, "WebServer", path => $"https://certus{path}");

        response.Identifier.Type.Should().Be("dns");
        response.Identifier.Value.Should().Be("example.com");
        response.Wildcard.Should().BeTrue();
    }

    [Fact]
    public async Task FinalizeOrder_WildcardOrder_ApexCsr_Rejected()
    {
        // Order authorized for the wildcard, CSR asks for the apex. The wildcard marker must not
        // be stripped during comparison, so this is a mismatch and finalize must fail.
        var order = await CreateReadyOrderAsync("*.example.com");
        var csr = BuildCsr("example.com");

        var (success, error) = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        success.Should().BeFalse();
        error.Should().Contain("SANs do not match");
    }

    [Fact]
    public async Task FinalizeOrder_NonWildcardOrder_WildcardCsr_Rejected()
    {
        // The dangerous direction: an apex authorization (satisfiable by HTTP-01) must not be able
        // to finalize a wildcard CSR, which would yield a wildcard cert that was never DNS-01 validated.
        var order = await CreateReadyOrderAsync("example.com");
        var csr = BuildCsr("*.example.com");

        var (success, error) = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        success.Should().BeFalse();
        error.Should().Contain("SANs do not match");
    }

    [Fact]
    public async Task FinalizeOrder_ExactMatch_Succeeds()
    {
        var order = await CreateReadyOrderAsync("example.com");
        var csr = BuildCsr("example.com");

        var (success, error) = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        success.Should().BeTrue();
        error.Should().BeNull();

        var updated = await _sut.GetOrderAsync(order.OrderId);
        updated!.Status.Should().Be("valid");
    }

    [Fact]
    public async Task FinalizeOrder_Expired_RejectedAndMarkedInvalid()
    {
        // A ready order that has passed its expiry must not finalize (RFC 8555 §7.1.3).
        var order = await CreateReadyOrderAsync("example.com");
        order.ExpiresAt = DateTime.UtcNow.AddMinutes(-1);
        await _db.SaveChangesAsync();
        var csr = BuildCsr("example.com");

        var (success, error) = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        success.Should().BeFalse();
        error.Should().Contain("expired");

        var updated = await _sut.GetOrderAsync(order.OrderId);
        updated!.Status.Should().Be("invalid");
    }

    #region Non-DNS SAN smuggling (issue #100)

    [Fact]
    public async Task FinalizeOrder_UpnOtherNameSan_Rejected()
    {
        // The crown jewel smuggle: a valid DNS name the client controls plus a
        // UPN otherName for a domain user. On an enrollee supplies subject
        // template that identity would be issued. The proxy must refuse it.
        var order = await CreateReadyOrderAsync("example.com");
        var csr = BuildCsrWithSanExtension("CN=example.com", w =>
        {
            WriteDnsName(w, "example.com");
            WriteUpnOtherName(w, "attacker@home.local");
        });

        var (success, error) = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        success.Should().BeFalse();
        error.Should().Contain("must not carry subject alternative names");
        var updated = await _sut.GetOrderAsync(order.OrderId);
        updated!.Status.Should().Be("ready");
        updated.AdcsRequestId.Should().BeNull();
    }

    [Fact]
    public async Task FinalizeOrder_IpAddressSan_Rejected()
    {
        var order = await CreateReadyOrderAsync("example.com");
        var csr = BuildCsrWithSanExtension("CN=example.com", w =>
        {
            WriteDnsName(w, "example.com");
            WriteIpAddress(w, new byte[] { 10, 0, 0, 1 });
        });

        var (success, error) = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        success.Should().BeFalse();
        error.Should().Contain("must not carry subject alternative names");
        (await _sut.GetOrderAsync(order.OrderId))!.Status.Should().Be("ready");
    }

    [Fact]
    public async Task FinalizeOrder_Rfc822NameSan_Rejected()
    {
        var order = await CreateReadyOrderAsync("example.com");
        var csr = BuildCsrWithSanExtension("CN=example.com", w =>
        {
            WriteDnsName(w, "example.com");
            WriteRfc822Name(w, "device@example.com");
        });

        var (success, error) = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        success.Should().BeFalse();
        error.Should().Contain("must not carry subject alternative names");
        (await _sut.GetOrderAsync(order.OrderId))!.Status.Should().Be("ready");
    }

    [Fact]
    public async Task FinalizeOrder_DirectoryNameSan_Rejected()
    {
        // A directoryName is refused like any other non DNS SAN. Depending on how
        // strictly BouncyCastle reads the explicit tag the wording may be the SAN
        // refusal or the parse refusal, so assert only that the raw DER is refused
        // and the order stays retryable.
        var order = await CreateReadyOrderAsync("example.com");
        var csr = BuildCsrWithSanExtension("CN=example.com", w =>
        {
            WriteDnsName(w, "example.com");
            WriteDirectoryName(w, "evil");
        });

        var (success, error) = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        success.Should().BeFalse();
        error.Should().NotBeNullOrEmpty();
        (await _sut.GetOrderAsync(order.OrderId))!.Status.Should().Be("ready");
    }

    [Fact]
    public async Task FinalizeOrder_PermanentIdentifierSan_Rejected()
    {
        // A device PermanentIdentifier is a recognized SAN type, but a dns order
        // authorizes no device identifier, so a matching DNS name does not save it.
        var order = await CreateReadyOrderAsync("example.com");
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var csr = DeviceCsrBuilder.Build(key, "CN=example.com", DeviceSerial, null, "example.com");

        var (success, error) = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        success.Should().BeFalse();
        error.Should().Contain("must not carry subject alternative names");
        (await _sut.GetOrderAsync(order.OrderId))!.Status.Should().Be("ready");
    }

    [Fact]
    public async Task FinalizeOrder_CnFallbackMasksHostileSan_Rejected()
    {
        // Before the fix a CSR with no DNS SAN fell back to the subject CN, so a
        // hostile non DNS SAN alongside a matching CN would pass. It must not.
        var order = await CreateReadyOrderAsync("example.com");
        var csr = BuildCsrWithSanExtension(
            "CN=example.com", w => WriteUpnOtherName(w, "attacker@home.local"));

        var (success, error) = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        success.Should().BeFalse();
        error.Should().Contain("must not carry subject alternative names");
        (await _sut.GetOrderAsync(order.OrderId))!.Status.Should().Be("ready");
    }

    [Fact]
    public async Task FinalizeOrder_CnOnlyNoSan_Succeeds()
    {
        // The CN fallback itself is unchanged: a CSR with no SAN extension at all
        // is still identified by its subject CN.
        var order = await CreateReadyOrderAsync("example.com");
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var csr = DeviceCsrBuilder.Build(key, "CN=example.com");

        var (success, error) = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        success.Should().BeTrue(error);
        (await _sut.GetOrderAsync(order.OrderId))!.Status.Should().Be("valid");
    }

    [Fact]
    public async Task FinalizeOrder_GarbageCsr_Rejected()
    {
        // A CSR that does not parse now returns a clean rejection (mapped to
        // badCSR by the controller) instead of escaping as a 500.
        var order = await CreateReadyOrderAsync("example.com");

        var (success, error) = await _sut.FinalizeOrderAsync(order.OrderId, new byte[] { 1, 2, 3 });

        success.Should().BeFalse();
        error.Should().Contain("could not be parsed");
        (await _sut.GetOrderAsync(order.OrderId))!.Status.Should().Be("ready");
    }

    [Fact]
    public async Task FinalizeOrder_HostileSan_NeverReachesTheCa()
    {
        // The raw DER must never be submitted to ADCS when the SAN check fails.
        var adcs = Substitute.For<IAdcsClient>();
        var sut = new OrderService(
            _db, adcs, _syncTrigger,
            new DeviceAttestationPolicyService(_db),
            new DomainPolicyAuditService(_db, NullLogger<DomainPolicyAuditService>.Instance),
            NullLogger<OrderService>.Instance);
        var order = await CreateReadyOrderAsync("example.com");
        var csr = BuildCsrWithSanExtension("CN=example.com", w =>
        {
            WriteDnsName(w, "example.com");
            WriteUpnOtherName(w, "attacker@home.local");
        });

        var (success, _) = await sut.FinalizeOrderAsync(order.OrderId, csr);

        success.Should().BeFalse();
        await adcs.DidNotReceive().SubmitCertificateRequestAsync(
            Arg.Any<string>(), Arg.Any<byte[]>(), Arg.Any<CancellationToken>());
    }

    #endregion

    #region Subject CN validation (issue #167)

    [Fact]
    public async Task FinalizeOrder_CnOutsideOrder_Rejected()
    {
        // The residual subject smuggle deferred from #100: the SAN matches the
        // order, so before the fix the CSR passed with an arbitrary CN, and on
        // an enrollee supplies subject template ADCS would have issued it.
        var order = await CreateReadyOrderAsync("example.com");
        var csr = BuildCsrWithSanExtension("CN=evil.attacker.test", w =>
            WriteDnsName(w, "example.com"));

        var (success, error) = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        success.Should().BeFalse();
        error.Should().Contain("subject CN");
        (await _sut.GetOrderAsync(order.OrderId))!.Status.Should().Be("ready");
    }

    [Fact]
    public async Task FinalizeOrder_DescriptiveCn_Rejected()
    {
        // Policy decision on issue #167: a descriptive CN is refused even though
        // it names no competing identifier. Public ACME CAs enforce the same
        // rule, so clients that work against them are unaffected.
        var order = await CreateReadyOrderAsync("example.com");
        var csr = BuildCsrWithSanExtension("CN=My Web Server", w =>
            WriteDnsName(w, "example.com"));

        var (success, error) = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        success.Should().BeFalse();
        error.Should().Contain("subject CN");
    }

    [Fact]
    public async Task FinalizeOrder_NoCn_SanOnly_Succeeds()
    {
        // Modern clients are SAN only. The CN rule applies only when a CN is
        // present, so a subject naming no CN keeps finalizing.
        var order = await CreateReadyOrderAsync("example.com");
        var csr = BuildCsrWithSanExtension("O=Certus Test", w =>
            WriteDnsName(w, "example.com"));

        var (success, error) = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        success.Should().BeTrue(error);
        (await _sut.GetOrderAsync(order.OrderId))!.Status.Should().Be("valid");
    }

    [Fact]
    public async Task FinalizeOrder_CnCaseDiffers_Succeeds()
    {
        // DNS names compare case insensitively; the CN check normalizes the
        // same way the SAN comparison does.
        var order = await CreateReadyOrderAsync("example.com");
        var csr = BuildCsrWithSanExtension("CN=EXAMPLE.COM", w =>
            WriteDnsName(w, "example.com"));

        var (success, error) = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        success.Should().BeTrue(error);
    }

    [Fact]
    public async Task FinalizeOrder_MultiCnNoSan_SecondCnDiffers_Rejected()
    {
        // The no SAN fallback identifies the CSR by its first CN alone, so
        // before the fix a second, different CN rode through unexamined and
        // both landed in the raw DER handed to ADCS. The subject string is
        // reversed on encoding, so the DER carries example.com first, which
        // is exactly the shape that slipped past the SetEquals check.
        var order = await CreateReadyOrderAsync("example.com");
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var csr = DeviceCsrBuilder.Build(key, "CN=evil.example, CN=example.com");

        var (success, error) = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        success.Should().BeFalse();
        error.Should().Contain("subject CN");
        (await _sut.GetOrderAsync(order.OrderId))!.Status.Should().Be("ready");
    }

    [Fact]
    public async Task FinalizeOrder_WildcardOrder_WildcardCn_Succeeds()
    {
        // Public CAs historically carry the wildcard name in the CN as well;
        // membership in the order's identifier set keeps that working, with
        // the wildcard marker compared verbatim.
        var order = await CreateReadyOrderAsync("*.example.com");
        var csr = BuildCsr("*.example.com");

        var (success, error) = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        success.Should().BeTrue(error);
    }

    [Fact]
    public async Task FinalizeOrder_HostileCn_NeverReachesTheCa()
    {
        // The raw DER must never be submitted to ADCS when the CN check fails.
        var adcs = Substitute.For<IAdcsClient>();
        var sut = new OrderService(
            _db, adcs, _syncTrigger,
            new DeviceAttestationPolicyService(_db),
            new DomainPolicyAuditService(_db, NullLogger<DomainPolicyAuditService>.Instance),
            NullLogger<OrderService>.Instance);
        var order = await CreateReadyOrderAsync("example.com");
        var csr = BuildCsrWithSanExtension("CN=evil.attacker.test", w =>
            WriteDnsName(w, "example.com"));

        var (success, _) = await sut.FinalizeOrderAsync(order.OrderId, csr);

        success.Should().BeFalse();
        await adcs.DidNotReceive().SubmitCertificateRequestAsync(
            Arg.Any<string>(), Arg.Any<byte[]>(), Arg.Any<CancellationToken>());
    }

    #endregion

    #region Finalize leaf guard (TLS capability ceiling)

    [Fact]
    public async Task FinalizeOrder_CeilingViolatingLeaf_FailsRevokesAndAudits()
    {
        // The mock CA minting a code signing leaf: the guard must keep the
        // certificate from the client, revoke it, create no ACME certificate
        // row, and write the finalize-guard audit row. Finalize itself
        // reports success with the failure on the order, the same contract
        // the CA retrieval failure path has always used.
        _adcsClient.LeafEkuOids = new[] { "1.3.6.1.5.5.7.3.3" };
        var order = await CreateReadyOrderAsync("guard.example.com");
        var csr = BuildCsr("guard.example.com");

        var (success, error) = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        success.Should().BeTrue(error);
        var updated = await _sut.GetOrderAsync(order.OrderId);
        updated!.Status.Should().Be("invalid");
        // A fragment with no apostrophe: the serializer's default encoder
        // escapes the apostrophe in the detail as a unicode sequence, so the
        // raw JSON never contains the human form of the whole sentence.
        updated.ErrorJson.Should().Contain("TLS certificate policy and was revoked");
        updated.CertificateId.Should().BeNull();
        (await _db.AcmeCertificates.AnyAsync(c => c.OrderId == order.Id)).Should().BeFalse();

        // The leaf the guard refused is the one that was revoked, reason 5.
        _adcsClient.RevokedSerials.Should().ContainSingle();

        var audit = await _db.DomainPolicyRejections.SingleAsync();
        audit.Stage.Should().Be("finalize-guard");
        audit.TemplateId.Should().Be("WebServer");
        audit.RejectedIdentifiers.Should().Contain("guard.example.com");
    }

    [Fact]
    public async Task FinalizeOrder_BareLeafWithNoEku_IsRefusedByTheGuard()
    {
        // No EKU extension means valid for every purpose, which the ceiling
        // refuses; before the mock grew leaf extensions this was every mock
        // issuance.
        _adcsClient.LeafEkuOids = null;
        var order = await CreateReadyOrderAsync("bare-guard.example.com");
        var csr = BuildCsr("bare-guard.example.com");

        await _sut.FinalizeOrderAsync(order.OrderId, csr);

        var updated = await _sut.GetOrderAsync(order.OrderId);
        updated!.Status.Should().Be("invalid");
        _adcsClient.RevokedSerials.Should().ContainSingle();
    }

    [Fact]
    public async Task FinalizeOrder_DefaultLeaf_PassesTheGuardAndDelivers()
    {
        // The mock's default extensions sit inside the ceiling, so the
        // ordinary path issues exactly as before the guard existed.
        var order = await CreateReadyOrderAsync("guard-pass.example.com");
        var csr = BuildCsr("guard-pass.example.com");

        var (success, error) = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        success.Should().BeTrue(error);
        var updated = await _sut.GetOrderAsync(order.OrderId);
        updated!.Status.Should().Be("valid");
        updated.CertificateId.Should().NotBeNull();
        _adcsClient.RevokedSerials.Should().BeEmpty();
        (await _db.DomainPolicyRejections.AnyAsync()).Should().BeFalse();
    }

    #endregion

    [Fact]
    public async Task GetOrderUrlsForAccount_ReturnsEveryOrderUrl()
    {
        var identifiers = new[] { new AcmeIdentifier { Type = "dns", Value = "example.com" } };
        var order1 = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);
        var order2 = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);

        var urls = await _sut.GetOrderUrlsForAccountAsync(_account.Id, path => $"https://certus{path}");

        urls.Should().HaveCount(2);
        urls.Should().Contain(u => u.Contains($"/order/{order1.OrderId}"));
        urls.Should().Contain(u => u.Contains($"/order/{order2.OrderId}"));
    }

    /// <summary>
    /// Creates an order for the given DNS identifiers and forces it into the "ready" state so the
    /// finalize path (which requires "ready") can be exercised directly.
    /// </summary>
    private async Task<AcmeOrder> CreateReadyOrderAsync(params string[] identifierValues)
    {
        var identifiers = identifierValues
            .Select(v => new AcmeIdentifier { Type = "dns", Value = v })
            .ToArray();
        var order = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);
        order.Status = "ready";
        await _db.SaveChangesAsync();
        return order;
    }

    #region Device order tests

    private const string DeviceSerial = "SN-DEVICE-0001";
    private const string DeviceTemplate = "WebServer";

    [Fact]
    public async Task CreateOrder_PermanentIdentifier_EmitsSingleDeviceChallenge()
    {
        var identifiers = new[]
        {
            new AcmeIdentifier { Type = "permanent-identifier", Value = DeviceSerial }
        };

        var order = await _sut.CreateOrderAsync(_account, DeviceTemplate, identifiers, null, null);

        var authz = order.Authorizations.Single();
        authz.IdentifierType.Should().Be("permanent-identifier");
        authz.IdentifierValue.Should().Be(DeviceSerial);
        authz.Wildcard.Should().BeFalse();
        authz.Challenges.Should().ContainSingle()
            .Which.Type.Should().Be("device-attest-01");
        authz.Challenges[0].Token.Should().NotBeNullOrEmpty();
        authz.Challenges[0].Status.Should().Be("pending");
    }

    [Fact]
    public async Task FinalizeDeviceOrder_CnBinding_CnMatches_Issues()
    {
        var (order, key) = await CreateReadyDeviceOrderAsync(CsrIdentifierBindingModes.CnOrSan);
        var csr = DeviceCsrBuilder.Build(key, $"CN={DeviceSerial}");

        var (success, error) = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        success.Should().BeTrue(error);
        (await _sut.GetOrderAsync(order.OrderId))!.Status.Should().Be("valid");
    }

    [Fact]
    public async Task FinalizeDeviceOrder_WrongKey_Rejected()
    {
        // The second leg of the three way binding: the CSR key must be the
        // attested key, with no configuration that can turn it off.
        var (order, _) = await CreateReadyDeviceOrderAsync(CsrIdentifierBindingModes.CnOrSan);
        using var otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var csr = DeviceCsrBuilder.Build(otherKey, $"CN={DeviceSerial}");

        var (success, error) = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        success.Should().BeFalse();
        error.Should().Contain("attested device key");
    }

    [Fact]
    public async Task FinalizeDeviceOrder_CnBinding_WrongCn_Rejected()
    {
        var (order, key) = await CreateReadyDeviceOrderAsync(CsrIdentifierBindingModes.CnOrSan);
        var csr = DeviceCsrBuilder.Build(key, "CN=SOME-OTHER-DEVICE");

        var (success, error) = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        success.Should().BeFalse();
        error.Should().Contain("subject CN does not match");
    }

    [Fact]
    public async Task FinalizeDeviceOrder_CnBinding_PiSanAlone_Issues()
    {
        var (order, key) = await CreateReadyDeviceOrderAsync(CsrIdentifierBindingModes.CnOrSan);
        var csr = DeviceCsrBuilder.Build(key, "O=Device Fleet", DeviceSerial);

        var (success, error) = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        success.Should().BeTrue(error);
    }

    [Fact]
    public async Task FinalizeDeviceOrder_CnBinding_IdentifierNowhere_Rejected()
    {
        var (order, key) = await CreateReadyDeviceOrderAsync(CsrIdentifierBindingModes.CnOrSan);
        var csr = DeviceCsrBuilder.Build(key, "O=Device Fleet");

        var (success, error) = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        success.Should().BeFalse();
        error.Should().Contain("must carry the order identifier");
    }

    [Fact]
    public async Task FinalizeDeviceOrder_SanRequired_CnOnly_Rejected()
    {
        var (order, key) = await CreateReadyDeviceOrderAsync(CsrIdentifierBindingModes.SanRequired);
        var csr = DeviceCsrBuilder.Build(key, $"CN={DeviceSerial}");

        var (success, error) = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        success.Should().BeFalse();
        error.Should().Contain("PermanentIdentifier");
    }

    [Fact]
    public async Task FinalizeDeviceOrder_SanRequired_WithPiSan_Issues()
    {
        var (order, key) = await CreateReadyDeviceOrderAsync(CsrIdentifierBindingModes.SanRequired);
        var csr = DeviceCsrBuilder.Build(key, $"CN={DeviceSerial}", DeviceSerial);

        var (success, error) = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        success.Should().BeTrue(error);
    }

    [Fact]
    public async Task FinalizeDeviceOrder_None_WithPiSan_Rejected()
    {
        var (order, key) = await CreateReadyDeviceOrderAsync(CsrIdentifierBindingModes.None);
        var csr = DeviceCsrBuilder.Build(key, "O=Device Fleet", DeviceSerial);

        var (success, error) = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        success.Should().BeFalse();
        error.Should().Contain("privacy");
    }

    [Fact]
    public async Task FinalizeDeviceOrder_None_CnNamesIdentifier_Rejected()
    {
        var (order, key) = await CreateReadyDeviceOrderAsync(CsrIdentifierBindingModes.None);
        var csr = DeviceCsrBuilder.Build(key, $"CN={DeviceSerial}");

        var (success, error) = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        success.Should().BeFalse();
        error.Should().Contain("privacy");
    }

    [Fact]
    public async Task FinalizeDeviceOrder_None_CleanCsr_Issues()
    {
        var (order, key) = await CreateReadyDeviceOrderAsync(CsrIdentifierBindingModes.None);
        var csr = DeviceCsrBuilder.Build(key, "O=Device Fleet");

        var (success, error) = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        success.Should().BeTrue(error);
    }

    [Fact]
    public async Task FinalizeDeviceOrder_DnsSan_AlwaysRejected()
    {
        // A dns SAN on a device CSR rejects in every binding mode: the
        // attestation said nothing about any host name.
        var (order, key) = await CreateReadyDeviceOrderAsync(CsrIdentifierBindingModes.CnOrSan);
        var csr = DeviceCsrBuilder.Build(
            key, $"CN={DeviceSerial}", null, null, "sneaky.example.com");

        var (success, error) = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        success.Should().BeFalse();
        error.Should().Contain("DNS");
    }

    [Fact]
    public async Task FinalizeDeviceOrder_WrongPiValue_Rejected()
    {
        // A wrong identifier value anywhere rejects, even when the CN is
        // right: the certificate would name a device the attestation never
        // vouched for.
        var (order, key) = await CreateReadyDeviceOrderAsync(CsrIdentifierBindingModes.CnOrSan);
        var csr = DeviceCsrBuilder.Build(key, $"CN={DeviceSerial}", "SOME-OTHER-DEVICE");

        var (success, error) = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        success.Should().BeFalse();
        error.Should().Contain("does not match the order identifier");
    }

    [Fact]
    public async Task FinalizeDeviceOrder_AssignerQualifiedIdentifier_MatchesStructuredSan()
    {
        // An order identifier in the full grammar form must octet match the
        // reassembly of the SAN's structured value and assigner fields.
        var qualified = $"{DeviceSerial}/1.3.6.1.4.1.99999.1";
        var (order, key) = await CreateReadyDeviceOrderAsync(
            CsrIdentifierBindingModes.SanRequired, qualified);
        var csr = DeviceCsrBuilder.Build(
            key, "O=Device Fleet", DeviceSerial, "1.3.6.1.4.1.99999.1");

        var (success, error) = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        success.Should().BeTrue(error);
    }

    [Fact]
    public async Task FinalizeDeviceOrder_ProfileRemoved_FailsClosed()
    {
        var (order, key) = await CreateReadyDeviceOrderAsync(CsrIdentifierBindingModes.CnOrSan);
        _db.DeviceAttestationProfiles.RemoveRange(_db.DeviceAttestationProfiles);
        await _db.SaveChangesAsync();
        var csr = DeviceCsrBuilder.Build(key, $"CN={DeviceSerial}");

        var (success, error) = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        success.Should().BeFalse();
        error.Should().Contain("no longer accepts device orders");
    }

    [Fact]
    public async Task FinalizeDeviceOrder_NoAttestedKey_FailsClosed()
    {
        var (order, key) = await CreateReadyDeviceOrderAsync(CsrIdentifierBindingModes.CnOrSan);
        order.Authorizations.Single().AttestedSpki = null;
        await _db.SaveChangesAsync();
        var csr = DeviceCsrBuilder.Build(key, $"CN={DeviceSerial}");

        var (success, error) = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        success.Should().BeFalse();
        error.Should().Contain("No attested device key");
    }

    [Fact]
    public async Task FinalizeDeviceOrder_GarbageCsr_Rejected()
    {
        var (order, _) = await CreateReadyDeviceOrderAsync(CsrIdentifierBindingModes.CnOrSan);

        var (success, error) = await _sut.FinalizeOrderAsync(
            order.OrderId, new byte[] { 1, 2, 3 });

        success.Should().BeFalse();
        error.Should().Contain("could not be parsed");
    }

    /// <summary>
    /// Seeds an enabled device attestation profile, creates a
    /// permanent-identifier order, marks its authorization valid with the
    /// returned key recorded as the attested key, and forces the order
    /// ready, so the finalize path can be exercised directly.
    /// </summary>
    private async Task<(AcmeOrder Order, ECDsa Key)> CreateReadyDeviceOrderAsync(
        string csrIdentifierBinding, string identifierValue = DeviceSerial)
    {
        _db.DeviceAttestationProfiles.Add(new DeviceAttestationProfile
        {
            TemplateId = DeviceTemplate,
            Enabled = true,
            GateMode = DeviceAttestationGateModes.Open,
            CsrIdentifierBinding = csrIdentifierBinding
        });
        await _db.SaveChangesAsync();

        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _deviceKeys.Add(key);

        var identifiers = new[]
        {
            new AcmeIdentifier { Type = "permanent-identifier", Value = identifierValue }
        };
        var order = await _sut.CreateOrderAsync(_account, DeviceTemplate, identifiers, null, null);

        var authz = order.Authorizations.Single();
        authz.Status = "valid";
        authz.AttestedSpki = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());
        authz.AttestationFormat = "apple";
        order.Status = "ready";
        await _db.SaveChangesAsync();

        return (order, key);
    }

    #endregion

    [Fact]
    public async Task RevokeCertificate_FiresSyncTrigger()
    {
        var certificate = await SeedCertificateAsync();

        var outcome = await _sut.RevokeCertificateAsync(certificate, reason: 0);

        outcome.Should().Be(RevokeOutcome.Revoked);
        certificate.RevokedAt.Should().NotBeNull();

        // The revoke path must nudge the inventory sync so the revocation
        // reaches the dashboard without waiting for the next timer tick.
        var fired = await _syncTrigger.WaitAsync(TimeSpan.FromMilliseconds(500), CancellationToken.None);
        fired.Should().BeTrue();
    }

    [Fact]
    public async Task RevokeCertificate_AlreadyRevoked_DoesNotFireTrigger()
    {
        var certificate = await SeedCertificateAsync();
        certificate.RevokedAt = DateTime.UtcNow.AddHours(-1);
        await _db.SaveChangesAsync();

        var outcome = await _sut.RevokeCertificateAsync(certificate, reason: 0);

        outcome.Should().Be(RevokeOutcome.AlreadyRevoked);

        var fired = await _syncTrigger.WaitAsync(TimeSpan.FromMilliseconds(100), CancellationToken.None);
        fired.Should().BeFalse();
    }

    /// <summary>Seeds an order with a stored certificate row, ready to revoke.</summary>
    private async Task<AcmeCertificate> SeedCertificateAsync()
    {
        var identifiers = new[] { new AcmeIdentifier { Type = "dns", Value = "example.com" } };
        var order = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);

        var certificate = new AcmeCertificate
        {
            CertificateId = "cert-revoke-test",
            OrderId = order.Id,
            CertificatePem = "-----BEGIN CERTIFICATE-----",
            AdcsRequestId = 42,
            SerialNumber = "AB01CD02EF03",
            IssuedAt = DateTime.UtcNow,
        };
        _db.AcmeCertificates.Add(certificate);
        await _db.SaveChangesAsync();
        return certificate;
    }

    /// <summary>
    /// Builds a signed PKCS#10 CSR whose subject CN is the first name and whose SAN extension
    /// contains all of the given DNS names (verbatim, including any wildcard marker).
    /// </summary>
    private static byte[] BuildCsr(params string[] dnsNames)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            $"CN={dnsNames[0]}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var sanBuilder = new SubjectAlternativeNameBuilder();
        foreach (var name in dnsNames)
            sanBuilder.AddDnsName(name);
        request.CertificateExtensions.Add(sanBuilder.Build());

        return request.CreateSigningRequest();
    }

    /// <summary>
    /// Builds a signed PKCS#10 CSR with the given subject and a Subject Alternative
    /// Name extension whose GeneralNames the caller writes raw. Lets a test express
    /// SAN shapes the typed builders cannot, such as a UPN otherName or an iPAddress
    /// alongside a DNS name. The key type is irrelevant: the dns path never inspects it.
    /// </summary>
    private static byte[] BuildCsrWithSanExtension(string subject, Action<AsnWriter> writeGeneralNames)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
            writeGeneralNames(writer);
        request.CertificateExtensions.Add(
            new X509Extension("2.5.29.17", writer.Encode(), critical: false));
        return request.CreateSigningRequest();
    }

    private static void WriteDnsName(AsnWriter writer, string dns) =>
        writer.WriteCharacterString(
            UniversalTagNumber.IA5String, dns, new Asn1Tag(TagClass.ContextSpecific, 2));

    private static void WriteRfc822Name(AsnWriter writer, string email) =>
        writer.WriteCharacterString(
            UniversalTagNumber.IA5String, email, new Asn1Tag(TagClass.ContextSpecific, 1));

    private static void WriteIpAddress(AsnWriter writer, byte[] address) =>
        writer.WriteOctetString(address, new Asn1Tag(TagClass.ContextSpecific, 7));

    private static void WriteUpnOtherName(AsnWriter writer, string upn)
    {
        // otherName carrying the Microsoft UPN type id, not a PermanentIdentifier.
        using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
        {
            writer.WriteObjectIdentifier("1.3.6.1.4.1.311.20.2.3");
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                writer.WriteCharacterString(UniversalTagNumber.UTF8String, upn);
        }
    }

    private static void WriteDirectoryName(AsnWriter writer, string commonName)
    {
        // directoryName is [4] EXPLICIT Name. Name is a CHOICE, so the tag is explicit.
        using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 4)))
        using (writer.PushSequence())
        using (writer.PushSetOf())
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier("2.5.4.3");
            writer.WriteCharacterString(UniversalTagNumber.UTF8String, commonName);
        }
    }

    public void Dispose()
    {
        _db.Dispose();
        _connection.Dispose();
        foreach (var key in _deviceKeys)
            key.Dispose();
    }
}

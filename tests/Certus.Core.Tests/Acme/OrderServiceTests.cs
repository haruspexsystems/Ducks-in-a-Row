using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certus.Core.Acme.Models;
using Certus.Core.Acme.Services;
using Certus.Core.Adcs;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Certus.Core.Services;
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
        _sut = new OrderService(_db, _adcsClient, _syncTrigger, NullLogger<OrderService>.Instance);

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

    public void Dispose()
    {
        _db.Dispose();
        _connection.Dispose();
    }
}

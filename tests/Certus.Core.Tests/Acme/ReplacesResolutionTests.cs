using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
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

/// <summary>
/// The service half of RFC 9773 §5: <see cref="OrderService.ResolveReplacesAsync"/>
/// admits a verified "replaces", refuses everything else, and what it admits is
/// persisted on the order and reflected by ToResponse, the section's MUST.
/// </summary>
public class ReplacesResolutionTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly CertusDbContext _db;
    private readonly OrderService _sut;
    private readonly AcmeAccount _account;
    private readonly AcmeAccount _otherAccount;

    public ReplacesResolutionTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();

        var dbOptions = new DbContextOptionsBuilder<CertusDbContext>()
            .UseSqlite(_connection)
            .Options;
        _db = new CertusDbContext(dbOptions);
        _db.Database.EnsureCreated();

        _sut = new OrderService(
            _db, new MockAdcsClient(), new CertificateSyncTrigger(), new CertificateRevocationGate(),
            new DeviceAttestationPolicyService(_db),
            new DomainPolicyAuditService(_db, NullLogger<DomainPolicyAuditService>.Instance),
            NullLogger<OrderService>.Instance);

        _account = SeedAccount("replaces-account-001");
        _otherAccount = SeedAccount("replaces-account-002");
    }

    [Fact]
    public async Task NoReplaces_IsNotPresent()
    {
        var (outcome, canonical) = await _sut.ResolveReplacesAsync(
            _account, Identifiers("renew.example.com"), null);

        outcome.Should().Be(ReplacesOutcome.NotPresent);
        canonical.Should().BeNull();
    }

    [Fact]
    public async Task VerifiedReplaces_ResolvesToTheCanonicalIdentifier()
    {
        var ariId = await SeedIssuedCertificateAsync(_account);

        var (outcome, canonical) = await _sut.ResolveReplacesAsync(
            _account, Identifiers("renew.example.com"), ariId);

        outcome.Should().Be(ReplacesOutcome.Resolved);
        canonical.Should().Be(ariId, "the stored form is rebuilt from the leaf's own octets");
    }

    [Fact]
    public async Task CreateOrder_PersistsReplaces_AndToResponseReflectsIt()
    {
        // RFC 9773 §5's MUST: reflect the accepted field in the response and in
        // every later fetch of the order.
        var ariId = await SeedIssuedCertificateAsync(_account);

        var order = await _sut.CreateOrderAsync(
            _account, "WebServer", Identifiers("renew.example.com"), null, null,
            replacesCertificateId: ariId);

        order.ReplacesCertificateId.Should().Be(ariId);

        var stored = await _db.AcmeOrders.AsNoTracking()
            .FirstAsync(o => o.Id == order.Id);
        stored.ReplacesCertificateId.Should().Be(ariId);

        OrderService.ToResponse(order, url => url).Replaces.Should().Be(ariId);
    }

    [Fact]
    public async Task OrdinaryOrder_ReflectsNoReplaces()
    {
        var order = await _sut.CreateOrderAsync(
            _account, "WebServer", Identifiers("plain.example.com"), null, null);

        OrderService.ToResponse(order, url => url).Replaces.Should().BeNull();
    }

    [Fact]
    public async Task MalformedIdentifier_IsRefused()
    {
        var (outcome, _) = await _sut.ResolveReplacesAsync(
            _account, Identifiers("renew.example.com"), "not-an-ari-identifier");

        outcome.Should().Be(ReplacesOutcome.Malformed);
    }

    [Fact]
    public async Task UnknownSerial_IsRefused()
    {
        // The RFC 9773 Appendix A example identifier: well formed, and no row
        // in this database carries its serial.
        var (outcome, _) = await _sut.ResolveReplacesAsync(
            _account, Identifiers("renew.example.com"),
            "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE");

        outcome.Should().Be(ReplacesOutcome.UnknownCertificate);
    }

    [Fact]
    public async Task MatchingSerialWithTheWrongKeyIdentifier_IsRefused()
    {
        // The serial finds the row, but the identifier names a different
        // issuer's certificate, so it is not the certificate we hold.
        var ariId = await SeedIssuedCertificateAsync(_account);
        AriCertificateId.TryParse(ariId, out _, out var serial).Should().BeTrue();
        var wrongIssuer = AriCertificateId.Format(new byte[] { 1, 2, 3, 4, 5 }, serial);

        var (outcome, _) = await _sut.ResolveReplacesAsync(
            _account, Identifiers("renew.example.com"), wrongIssuer);

        outcome.Should().Be(ReplacesOutcome.UnknownCertificate);
    }

    [Fact]
    public async Task AnotherAccountsCertificate_IsRefused()
    {
        var ariId = await SeedIssuedCertificateAsync(_otherAccount);

        var (outcome, _) = await _sut.ResolveReplacesAsync(
            _account, Identifiers("renew.example.com"), ariId);

        outcome.Should().Be(ReplacesOutcome.NotOwned);
    }

    [Fact]
    public async Task NoSharedIdentifier_IsRefused()
    {
        var ariId = await SeedIssuedCertificateAsync(_account);

        var (outcome, _) = await _sut.ResolveReplacesAsync(
            _account, Identifiers("unrelated.example.com"), ariId);

        outcome.Should().Be(ReplacesOutcome.NoSharedIdentifier);
    }

    [Fact]
    public async Task SharedDnsIdentifier_MatchesCaseInsensitively_AndTrimmed()
    {
        // The same normalization the finalize applies when matching a CSR's
        // names to an order, so a renewal cannot pass one gate and fail the
        // other over casing or stray whitespace.
        var ariId = await SeedIssuedCertificateAsync(_account);

        var (outcome, _) = await _sut.ResolveReplacesAsync(
            _account, Identifiers("  RENEW.EXAMPLE.COM  "), ariId);

        outcome.Should().Be(ReplacesOutcome.Resolved);
    }

    [Fact]
    public async Task ACertificateAlreadyNamedByALiveOrder_IsRefused()
    {
        var ariId = await SeedIssuedCertificateAsync(_account);
        await _sut.CreateOrderAsync(
            _account, "WebServer", Identifiers("renew.example.com"), null, null,
            replacesCertificateId: ariId);

        var (outcome, _) = await _sut.ResolveReplacesAsync(
            _account, Identifiers("renew.example.com"), ariId);

        outcome.Should().Be(ReplacesOutcome.AlreadyReplaced);
    }

    [Fact]
    public async Task AnExpiredAbandonedOrder_DoesNotMarkTheCertificateReplaced()
    {
        // Order expiry is lazy in this schema: the finalize checks it per read
        // and nothing ever writes it back as a status, so a pending order
        // whose client died stays "pending" in storage for ever. Counting it
        // as a live replacement would 409 every later renewal of the
        // certificate for the life of the database.
        var ariId = await SeedIssuedCertificateAsync(_account);
        var abandoned = await _sut.CreateOrderAsync(
            _account, "WebServer", Identifiers("renew.example.com"), null, null,
            replacesCertificateId: ariId);
        abandoned.ExpiresAt = DateTime.UtcNow.AddMinutes(-1);
        await _db.SaveChangesAsync();

        var (outcome, _) = await _sut.ResolveReplacesAsync(
            _account, Identifiers("renew.example.com"), ariId);

        outcome.Should().Be(ReplacesOutcome.Resolved);
    }

    [Fact]
    public async Task AValidOrderOlderThanItsExpiry_StillBlocks()
    {
        // The expiry carve-out must not overshoot: a completed replacement
        // stays a replacement for ever, however old its order row is.
        var ariId = await SeedIssuedCertificateAsync(_account);
        var completed = await _sut.CreateOrderAsync(
            _account, "WebServer", Identifiers("renew.example.com"), null, null,
            replacesCertificateId: ariId);
        completed.Status = "valid";
        completed.ExpiresAt = DateTime.UtcNow.AddDays(-30);
        await _db.SaveChangesAsync();

        var (outcome, _) = await _sut.ResolveReplacesAsync(
            _account, Identifiers("renew.example.com"), ariId);

        outcome.Should().Be(ReplacesOutcome.AlreadyReplaced);
    }

    [Fact]
    public async Task AnInvalidOrder_DoesNotMarkTheCertificateReplaced()
    {
        // §5's own carve out: "marked as replaced by a different Order that is
        // not 'invalid'". A failed replacement attempt must not lock the
        // certificate out of ever being replaced.
        var ariId = await SeedIssuedCertificateAsync(_account);
        var failed = await _sut.CreateOrderAsync(
            _account, "WebServer", Identifiers("renew.example.com"), null, null,
            replacesCertificateId: ariId);
        failed.Status = "invalid";
        await _db.SaveChangesAsync();

        var (outcome, _) = await _sut.ResolveReplacesAsync(
            _account, Identifiers("renew.example.com"), ariId);

        outcome.Should().Be(ReplacesOutcome.Resolved);
    }

    private static AcmeIdentifier[] Identifiers(params string[] values)
    {
        return values
            .Select(v => new AcmeIdentifier { Type = "dns", Value = v })
            .ToArray();
    }

    private AcmeAccount SeedAccount(string accountId)
    {
        var account = new AcmeAccount
        {
            AccountId = accountId,
            JwkJson = """{"kty":"RSA","n":"test","e":"AQAB"}""",
            JwkThumbprint = "thumb-" + accountId,
            Status = "valid",
            CreatedAt = DateTime.UtcNow
        };
        _db.AcmeAccounts.Add(account);
        _db.SaveChanges();
        return account;
    }

    /// <summary>
    /// Seeds the shape production leaves behind after an issuance: a valid
    /// order for "renew.example.com" and its certificate row, whose leaf
    /// carries the Authority Key Identifier the ARI identifier is built from.
    /// </summary>
    private async Task<string> SeedIssuedCertificateAsync(AcmeAccount owner)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=renew.example.com", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(
            X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(
                RandomNumberGenerator.GetBytes(20)));
        using var leaf = request.Create(
            new X500DistinguishedName("CN=renew.example.com"),
            X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pkcs1),
            DateTimeOffset.UtcNow.AddDays(-30),
            DateTimeOffset.UtcNow.AddDays(335),
            RandomNumberGenerator.GetBytes(12));

        var order = new AcmeOrder
        {
            OrderId = Guid.NewGuid().ToString("N"),
            AccountId = owner.Id,
            Status = "valid",
            TemplateId = "WebServer",
            IdentifiersJson = JsonSerializer.Serialize(Identifiers("renew.example.com")),
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddDays(7)
        };
        _db.AcmeOrders.Add(order);
        await _db.SaveChangesAsync();

        _db.AcmeCertificates.Add(new AcmeCertificate
        {
            CertificateId = Guid.NewGuid().ToString("N"),
            OrderId = order.Id,
            CertificatePem = leaf.ExportCertificatePem(),
            AdcsRequestId = Random.Shared.Next(100000, 999999),
            SerialNumber = leaf.SerialNumber,
            IssuedAt = DateTime.UtcNow
        });
        await _db.SaveChangesAsync();

        return AriCertificateId.FromCertificate(leaf)!;
    }

    public void Dispose()
    {
        _db.Dispose();
        _connection.Dispose();
        GC.SuppressFinalize(this);
    }
}

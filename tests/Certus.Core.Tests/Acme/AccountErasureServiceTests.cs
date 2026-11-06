using System.Text.Json;
using Certus.Core.Acme.Models;
using Certus.Core.Acme.Services;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;

namespace Certus.Core.Tests.Acme;

/// <summary>
/// The per account erasure path (issue #637, CRA risk R18): the personal data
/// is gone, the issuance records stay, the account has to be deactivated first,
/// and the log line that stands in for the audit row until #634 names the actor.
/// </summary>
public class AccountErasureServiceTests : IDisposable
{
    private static readonly DateTime Now = new(2026, 10, 23, 12, 0, 0, DateTimeKind.Utc);

    private readonly SqliteConnection _connection;
    private readonly DbContextOptions<CertusDbContext> _dbOptions;
    private readonly CertusDbContext _db;
    private readonly RecordingLogger _logger = new();
    private readonly AccountErasureService _sut;

    public AccountErasureServiceTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _dbOptions = new DbContextOptionsBuilder<CertusDbContext>().UseSqlite(_connection).Options;
        _db = new CertusDbContext(_dbOptions);
        _db.Database.EnsureCreated();
        _sut = new AccountErasureService(_db, _logger, new FakeTimeProvider(new DateTimeOffset(Now)));
    }

    public void Dispose()
    {
        _db.Dispose();
        _connection.Dispose();
        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task Erase_UnknownAccount_IsNotFound()
    {
        var result = await _sut.EraseAsync(9999, "CORP\\admin");

        result.Outcome.Should().Be(AccountErasureOutcome.NotFound);
    }

    [Fact]
    public async Task Erase_AValidAccount_IsRefused_AndChangesNothing()
    {
        var account = SeedAccount("valid", contact: "[\"mailto:live@example.com\"]");
        SeedDeviceOrder(account, "valid");

        var result = await _sut.EraseAsync(account.Id, "CORP\\admin");

        result.Outcome.Should().Be(AccountErasureOutcome.NotDeactivated);
        await using var verify = new CertusDbContext(_dbOptions);
        (await verify.AcmeAccounts.SingleAsync(a => a.Id == account.Id)).ContactJson.Should().Be("[\"mailto:live@example.com\"]");
        (await verify.AcmeAuthorizations.SingleAsync()).IdentifierValue.Should().Be("C02XYZ123");
        _logger.Lines.Should().BeEmpty();
    }

    [Fact]
    public async Task Erase_RemovesThePersonalData_AndKeepsTheIssuanceRecords()
    {
        var credential = SeedCredential(principal: ("S-1-5-21-1-2-3-1001", "CORP\\jdoe", "user"));
        var account = SeedAccount("deactivated", contact: "[\"mailto:jdoe@example.com\"]",
            credential: credential, deactivatedAt: Now.AddDays(-10));
        var order = SeedDeviceOrder(account, "valid");
        var certificateRow = _db.AcmeCertificates.Single(c => c.OrderId == order.Id);

        var result = await _sut.EraseAsync(account.Id, "CORP\\admin");

        result.Outcome.Should().Be(AccountErasureOutcome.Erased);
        result.OrdersRedacted.Should().Be(1);
        result.AuthorizationsRedacted.Should().Be(1);
        result.ChallengesRedacted.Should().Be(1);
        result.CredentialLinkCleared.Should().BeTrue();

        await using var verify = new CertusDbContext(_dbOptions);

        // Gone: contacts, the principal link, the identifiers and attestation.
        var erased = await verify.AcmeAccounts.SingleAsync(a => a.Id == account.Id);
        erased.ContactJson.Should().BeNull();
        erased.ErasedAt.Should().Be(Now);
        erased.UpdatedAt.Should().Be(Now.AddDays(-10),
            "the deactivation instant is the retention clock and erasure must not restart it");
        var link = await verify.EabCredentials.SingleAsync(c => c.Id == credential.Id);
        link.AdPrincipalSid.Should().BeNull();
        link.AdPrincipalName.Should().BeNull();
        link.AdPrincipalType.Should().BeNull();
        var authorization = await verify.AcmeAuthorizations.SingleAsync(a => a.OrderId == order.Id);
        authorization.IdentifierValue.Should().BeEmpty();
        authorization.AttestedSpki.Should().BeNull();
        authorization.AttestedPropertiesJson.Should().BeNull();
        authorization.AttestationFormat.Should().BeNull();
        var challenge = await verify.AcmeChallenges.SingleAsync(c => c.AuthorizationId == authorization.Id);
        challenge.AttestationObject.Should().BeNull();

        // Kept: the order row, the certificate record and the shape of the order.
        var keptOrder = await verify.AcmeOrders.SingleAsync(o => o.Id == order.Id);
        keptOrder.Status.Should().Be("valid");
        keptOrder.AdcsRequestId.Should().Be(order.AdcsRequestId);
        keptOrder.CertificateId.Should().Be(order.CertificateId);
        keptOrder.CsrDer.Should().BeNull();
        var identifiers = JsonSerializer.Deserialize<List<AcmeIdentifier>>(keptOrder.IdentifiersJson)!;
        identifiers.Should().ContainSingle()
            .Which.Should().BeEquivalentTo(new AcmeIdentifier { Type = "permanent-identifier", Value = "" },
                "the type says it was a device order; the value was the device");
        var keptCertificate = await verify.AcmeCertificates.SingleAsync(c => c.OrderId == order.Id);
        keptCertificate.SerialNumber.Should().Be(certificateRow.SerialNumber);
        keptCertificate.AdcsRequestId.Should().Be(certificateRow.AdcsRequestId);
        keptCertificate.CertificatePem.Should().Be(certificateRow.CertificatePem);
        authorization.IdentifierType.Should().Be("permanent-identifier");
        challenge.Type.Should().Be("device-attest-01");

        // The record of the action, at Warning so a raised level keeps it.
        _logger.Lines.Should().ContainSingle(l => l.Level == LogLevel.Warning)
            .Which.Message.Should().Contain(account.AccountId).And.Contain("CORP\\admin");
    }

    [Fact]
    public async Task Erase_ASecondTime_ReportsTheFirstErasure_AndChangesNothing()
    {
        var account = SeedAccount("deactivated", contact: "[\"mailto:once@example.com\"]",
            deactivatedAt: Now.AddDays(-10));
        (await _sut.EraseAsync(account.Id, "CORP\\admin")).Outcome.Should().Be(AccountErasureOutcome.Erased);
        _logger.Lines.Clear();

        var again = await _sut.EraseAsync(account.Id, "CORP\\other");

        again.Outcome.Should().Be(AccountErasureOutcome.AlreadyErased);
        again.Account!.ErasedAt.Should().Be(Now);
        again.OrdersRedacted.Should().Be(0);
        _logger.Lines.Should().BeEmpty("nothing happened, so nothing is recorded");
    }

    [Fact]
    public async Task Erase_InsideACallersTransaction_JoinsIt_SoARollbackUndoesTheErasure()
    {
        // The dashboard's audit filter opens the transaction before the action
        // runs (issue #634); the erasure must land in it, so the audit row and
        // the erasure commit or roll back together.
        var account = SeedAccount("deactivated", contact: "[\"mailto:person@example.com\"]",
            deactivatedAt: Now.AddDays(-10));

        await using (var tx = await _db.Database.BeginTransactionAsync())
        {
            var result = await _sut.EraseAsync(account.Id, "CORP\\admin");
            result.Outcome.Should().Be(AccountErasureOutcome.Erased);
            _db.Database.CurrentTransaction.Should().BeSameAs(tx, "the service joined rather than replaced it");
            await tx.RollbackAsync();
        }

        await using var verify = new CertusDbContext(_dbOptions);
        var row = await verify.AcmeAccounts.SingleAsync(a => a.Id == account.Id);
        row.ContactJson.Should().Be("[\"mailto:person@example.com\"]");
        row.ErasedAt.Should().BeNull();
    }

    [Fact]
    public async Task Erase_WithNoCredential_ReportsNoLinkCleared()
    {
        var account = SeedAccount("deactivated", contact: null, deactivatedAt: Now.AddDays(-1));

        var result = await _sut.EraseAsync(account.Id, "CORP\\admin");

        result.Outcome.Should().Be(AccountErasureOutcome.Erased);
        result.CredentialLinkCleared.Should().BeFalse();
    }

    [Fact]
    public async Task Erase_ClearsTheLinkForEveryAccountBoundToTheCredential()
    {
        // The link names the person the credential was handed to, and one
        // credential may bind many accounts, so the documentation says that
        // erasing one account clears it for all of them.
        var credential = SeedCredential(principal: ("S-1-5-21-1-2-3-1002", "CORP\\shared", "group"));
        var erasedAccount = SeedAccount("deactivated", contact: null, credential: credential, deactivatedAt: Now);
        SeedAccount("valid", contact: "[\"mailto:other@example.com\"]", credential: credential);

        await _sut.EraseAsync(erasedAccount.Id, "CORP\\admin");

        await using var verify = new CertusDbContext(_dbOptions);
        (await verify.EabCredentials.SingleAsync(c => c.Id == credential.Id)).AdPrincipalSid.Should().BeNull();
    }

    [Theory]
    [InlineData("""[{"type":"dns","value":"www.example.com"},{"type":"permanent-identifier","value":"ABC"}]""",
        """[{"type":"dns","value":""},{"type":"permanent-identifier","value":""}]""")]
    [InlineData("not json", "[]")]
    [InlineData("[]", "[]")]
    public void RedactIdentifiers_KeepsTheTypes_AndBlanksTheValues(string stored, string expected)
    {
        AccountErasureService.RedactIdentifiers(stored).Should().Be(expected);
    }

    // ---- Helpers ----

    private AcmeAccount SeedAccount(
        string status, string? contact, EabCredential? credential = null, DateTime? deactivatedAt = null)
    {
        var account = new AcmeAccount
        {
            AccountId = Guid.NewGuid().ToString("N"),
            JwkJson = """{"kty":"RSA","n":"test","e":"AQAB"}""",
            JwkThumbprint = Guid.NewGuid().ToString("N"),
            Status = status,
            ContactJson = contact,
            ExternalAccountCredentialId = credential?.Id,
            CreatedAt = Now.AddDays(-100),
            UpdatedAt = deactivatedAt,
        };
        _db.AcmeAccounts.Add(account);
        _db.SaveChanges();
        return account;
    }

    private EabCredential SeedCredential((string Sid, string Name, string Type) principal)
    {
        var credential = new EabCredential
        {
            KeyId = Guid.NewGuid().ToString("N"),
            Name = "devices",
            SecretProtected = "protected",
            AdPrincipalSid = principal.Sid,
            AdPrincipalName = principal.Name,
            AdPrincipalType = principal.Type,
            CreatedAt = Now.AddDays(-200),
        };
        _db.EabCredentials.Add(credential);
        _db.SaveChanges();
        return credential;
    }

    /// <summary>
    /// A device order as the attestation path leaves it: the serial in the
    /// identifier list and on the authorization, the attested facts beside it,
    /// the attestation object on the challenge, and the issued leaf stored.
    /// </summary>
    private AcmeOrder SeedDeviceOrder(AcmeAccount owner, string status)
    {
        var order = new AcmeOrder
        {
            OrderId = Guid.NewGuid().ToString("N"),
            AccountId = owner.Id,
            Status = status,
            TemplateId = "Devices",
            IdentifiersJson = """[{"type":"permanent-identifier","value":"C02XYZ123"}]""",
            CsrDer = Convert.ToBase64String([1, 2, 3]),
            AdcsRequestId = 777,
            CertificateId = Guid.NewGuid().ToString("N"),
            CreatedAt = Now.AddDays(-20),
            ExpiresAt = Now.AddDays(-13),
            Authorizations =
            {
                new AcmeAuthorization
                {
                    AuthorizationId = Guid.NewGuid().ToString("N"),
                    IdentifierType = "permanent-identifier",
                    IdentifierValue = "C02XYZ123",
                    Status = "valid",
                    AttestedSpki = "spki",
                    AttestationFormat = "apple",
                    AttestedPropertiesJson = """{"serialNumber":"C02XYZ123","udid":"0000-0001"}""",
                    CreatedAt = Now.AddDays(-20),
                    ExpiresAt = Now.AddDays(-13),
                    Challenges =
                    {
                        new AcmeChallenge
                        {
                            ChallengeId = Guid.NewGuid().ToString("N"),
                            Type = "device-attest-01",
                            Token = "token",
                            Status = "valid",
                            AttestationObject = "attestation-bytes",
                        },
                    },
                },
            },
        };
        _db.AcmeOrders.Add(order);
        _db.SaveChanges();

        _db.AcmeCertificates.Add(new AcmeCertificate
        {
            CertificateId = order.CertificateId!,
            OrderId = order.Id,
            CertificatePem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
            AdcsRequestId = 777,
            SerialNumber = "1A2B",
            IssuedAt = Now.AddDays(-19),
        });
        _db.SaveChanges();
        return order;
    }

    private sealed class RecordingLogger : ILogger<AccountErasureService>
    {
        public List<(LogLevel Level, string Message)> Lines { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            lock (Lines)
                Lines.Add((logLevel, formatter(state, exception)));
        }
    }
}

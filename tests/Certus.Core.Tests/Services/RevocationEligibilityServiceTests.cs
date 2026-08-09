using Certus.Core.Acme.Services;
using Certus.Core.Adcs;
using Certus.Core.Configuration;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Certus.Core.Services;
using Certus.Core.Setup;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using NSubstitute.ExceptionExtensions;

namespace Certus.Core.Tests.Services;

/// <summary>
/// The revocation scope legs of RevocationEligibilityService: the provenance
/// and enabled template union under ducks-managed, the custom list, all mode
/// staying under the ceiling, the dual form template mapping through the
/// CA's published list, and the fail closed degradation when the CA is
/// unreachable. The ceiling half (capability sources, refusal messages) is
/// covered by the revocation integration tests and TlsCapabilityCeilingTests.
/// </summary>
public class RevocationEligibilityServiceTests : IDisposable
{
    private const string ServerAuth = "1.3.6.1.5.5.7.3.1";

    private readonly SqliteConnection _connection;
    private readonly CertusDbContext _db;
    private readonly string _tempDir;
    private readonly CertusOptions _options;

    public RevocationEligibilityServiceTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _db = new CertusDbContext(new DbContextOptionsBuilder<CertusDbContext>()
            .UseSqlite(_connection).Options);
        _db.Database.EnsureCreated();

        _tempDir = Path.Combine(Path.GetTempPath(), $"certus-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
        _options = new CertusOptions { DatabasePath = Path.Combine(_tempDir, "certus.db") };
    }

    public void Dispose()
    {
        _db.Dispose();
        _connection.Dispose();
        try
        {
            Directory.Delete(_tempDir, recursive: true);
        }
        catch (IOException)
        {
            // Best effort: a stray temp folder is harmless.
        }
    }

    private void WriteStatus(
        string? scope, List<string>? revocable = null, List<string>? enabled = null)
    {
        new SetupStatus
        {
            SetupCompleted = true,
            EnabledTemplates = enabled ?? [],
            RevocationScope = scope,
            RevocableTemplates = revocable ?? [],
        }.Save(SetupStatus.GetStatusPath(_options));
    }

    /// <summary>
    /// Builds the service. The default CA offers WebServer with the display
    /// name "Web Server", the mock's own pairing, so the dual form mapping
    /// has something real to resolve against; pass a substitute client to
    /// simulate CA failures.
    /// </summary>
    private RevocationEligibilityService BuildService(IAdcsClient? adcsClient = null)
    {
        var enabledTemplates = new EnabledTemplatesPolicy(
            Options.Create(_options), Options.Create(new AcmeOptions()),
            NullLogger<EnabledTemplatesPolicy>.Instance);
        return new RevocationEligibilityService(
            _db,
            new TemplateService(adcsClient ?? new MockAdcsClient(), enabledTemplates,
                NullLogger<TemplateService>.Instance),
            new RevocationScopePolicy(
                Options.Create(_options), NullLogger<RevocationScopePolicy>.Instance),
            NullLogger<RevocationEligibilityService>.Instance);
    }

    /// <summary>An issued row that passes the ceiling from its columns.</summary>
    private static SyncedCertificate TlsRow(string templateName, int requestId = 4711) => new()
    {
        RequestId = requestId,
        SerialNumber = "0dc0ffee000000aa",
        Subject = "CN=scope.example.test",
        TemplateName = templateName,
        Status = "Issued",
        NotBefore = DateTime.UtcNow,
        NotAfter = DateTime.UtcNow.AddYears(1),
        RequestDate = DateTime.UtcNow,
        ExtendedKeyUsageOids = ServerAuth,
        KeyUsage = 160,
    };

    [Fact]
    public async Task DucksManaged_AcmeIssuedRow_IsInScope()
    {
        // The provenance leg: an AcmeCertificates row bridges by request id,
        // with no template lookup involved.
        WriteStatus("ducks-managed", enabled: []);
        _db.AcmeCertificates.Add(new AcmeCertificate
        {
            CertificateId = "elig-test-cert",
            CertificatePem = "PEM",
            AdcsRequestId = 4711,
            Order = new AcmeOrder
            {
                OrderId = "elig-test-order",
                Status = "valid",
                TemplateId = "SomethingElse",
                ExpiresAt = DateTime.UtcNow.AddDays(1),
                Account = new AcmeAccount
                {
                    AccountId = "elig-test-acct",
                    JwkJson = "{}",
                    JwkThumbprint = "elig-test-thumb",
                },
            },
        });
        await _db.SaveChangesAsync();

        var result = await BuildService().EvaluateAsync(TlsRow("Unrelated Template"));

        result.Allowed.Should().BeTrue();
    }

    [Fact]
    public async Task DucksManaged_RawTemplateMatch_IsInScope()
    {
        WriteStatus("ducks-managed", enabled: ["Web Server"]);

        var result = await BuildService().EvaluateAsync(TlsRow("Web Server"));

        result.Allowed.Should().BeTrue();
    }

    [Fact]
    public async Task DucksManaged_DisplayNameMapsToCanonicalEntry_IsInScope()
    {
        // The wizard stores the canonical name (WebServer) while the synced
        // row carries the resolved display name (Web Server); the mapping
        // through the CA's published list must bridge the two forms.
        WriteStatus("ducks-managed", enabled: ["WebServer"]);

        var result = await BuildService().EvaluateAsync(TlsRow("Web Server"));

        result.Allowed.Should().BeTrue();
    }

    [Fact]
    public async Task DucksManaged_NeitherLeg_IsOutOfScope()
    {
        WriteStatus("ducks-managed", enabled: ["WebServer"]);

        var result = await BuildService().EvaluateAsync(TlsRow("Domain Controller"));

        result.Allowed.Should().BeFalse();
        result.BlockedKind.Should().Be("out-of-scope");
        result.Detail.Should().Contain("ducks-managed").And.Contain("Settings");
    }

    [Fact]
    public async Task Custom_ListedTemplate_IsInScope()
    {
        WriteStatus("custom", revocable: ["Domain Controller"]);

        var result = await BuildService().EvaluateAsync(TlsRow("Domain Controller"));

        result.Allowed.Should().BeTrue();
    }

    [Fact]
    public async Task Custom_UnlistedTemplate_IsOutOfScope()
    {
        WriteStatus("custom", revocable: ["Web Server"]);

        var result = await BuildService().EvaluateAsync(TlsRow("Domain Controller"));

        result.Allowed.Should().BeFalse();
        result.BlockedKind.Should().Be("out-of-scope");
        result.Detail.Should().Contain("revocable template list");
    }

    [Fact]
    public async Task Custom_EmptyList_RefusesEverything()
    {
        // Custom with nothing ticked means dashboard revocation is disabled
        // entirely; it fails safe rather than falling back to another mode.
        WriteStatus("custom", revocable: []);

        var result = await BuildService().EvaluateAsync(TlsRow("Web Server"));

        result.Allowed.Should().BeFalse();
        result.BlockedKind.Should().Be("out-of-scope");
    }

    [Fact]
    public async Task All_CeilingPassingRow_IsInScope()
    {
        WriteStatus("all");

        var result = await BuildService().EvaluateAsync(TlsRow("Domain Controller"));

        result.Allowed.Should().BeTrue();
    }

    [Fact]
    public async Task All_CeilingViolatingRow_StaysBlockedByGuardrail()
    {
        // The ceiling always wins: even in all mode a smart card logon
        // certificate is refused, and the reason is the guardrail, not the
        // scope, because no settings change can fix it.
        WriteStatus("all");
        var row = TlsRow("Web Server");
        row.ExtendedKeyUsageOids = "1.3.6.1.5.5.7.3.2, 1.3.6.1.4.1.311.20.2.2";

        var result = await BuildService().EvaluateAsync(row);

        result.Allowed.Should().BeFalse();
        result.BlockedKind.Should().Be("guardrail");
        result.Detail.Should().Contain("smart card logon");
    }

    [Fact]
    public async Task MissingStatusFile_DefaultsToDucksManaged()
    {
        // No file at all: the narrow default applies, and with no enabled
        // set and no provenance the row is out of scope.
        var result = await BuildService().EvaluateAsync(TlsRow("Web Server"));

        result.Allowed.Should().BeFalse();
        result.BlockedKind.Should().Be("out-of-scope");
    }

    [Fact]
    public async Task CaUnreachable_DegradesToTheRawMatch()
    {
        // The canonical entry needs the CA list to map the display name; with
        // the CA down the raw miss stands and the row reads out of scope
        // (fail closed, and the revocation itself would fail anyway).
        WriteStatus("ducks-managed", enabled: ["WebServer"]);
        var throwing = Substitute.For<IAdcsClient>();
        throwing.GetTemplatesAsync(Arg.Any<CancellationToken>())
            .ThrowsAsync(new CaUnavailableException("CA is down"));

        var mapped = await BuildService(throwing).EvaluateAsync(TlsRow("Web Server"));
        mapped.Allowed.Should().BeFalse();
        mapped.BlockedKind.Should().Be("out-of-scope");

        // A raw form entry still matches without any CA involvement.
        WriteStatus("ducks-managed", enabled: ["Web Server"]);
        BumpWriteTime();
        var raw = await BuildService(throwing).EvaluateAsync(TlsRow("Web Server"));
        raw.Allowed.Should().BeTrue();
    }

    private void BumpWriteTime()
    {
        var path = SetupStatus.GetStatusPath(_options);
        File.SetLastWriteTimeUtc(path, File.GetLastWriteTimeUtc(path).AddSeconds(1));
    }
}

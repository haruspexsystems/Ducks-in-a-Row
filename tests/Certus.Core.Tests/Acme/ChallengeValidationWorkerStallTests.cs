using Certus.Core.Acme.Services;
using Certus.Core.Adcs;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Certus.Core.Services;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Certus.Core.Tests.Acme;

/// <summary>
/// The validation worker's answer to one challenge whose validator throws.
///
/// The CRA risk assessment (R04, issue #632) marked this unproven: the worker
/// catches at the loop level, so an exception a validator lets out (an
/// IOException from a TLS handshake that dies mid stream is the known case)
/// was thought to abort the sweep or kill the worker. Measured on main at
/// 96e7fe9: the worker survived, but the sweep did not. One throwing challenge
/// ended the pass, every challenge loaded after it went unvalidated, and the
/// next pass loaded the same list in the same order, so the stall repeated
/// every tick until the order expired a week later. The fix is a catch per
/// challenge; these tests drive the real sweep through a real scope so the
/// loop itself, not a single challenge, is what is under test.
/// </summary>
public class ChallengeValidationWorkerStallTests : IDisposable
{
    private const string StallingDomain = "stall.example.com";
    private const string NextDomain = "next.example.com";

    private readonly SqliteConnection _connection;
    private readonly ServiceProvider _provider;
    private readonly ChallengeValidationService _sut;
    private readonly ThrowingValidator _validator = new();

    public ChallengeValidationWorkerStallTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();

        var services = new ServiceCollection();
        services.AddDbContext<CertusDbContext>(o => o.UseSqlite(_connection));
        services.AddSingleton<ILoggerFactory, NullLoggerFactory>();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        services.AddSingleton<IAdcsClient, MockAdcsClient>();
        services.AddSingleton<CertificateSyncTrigger>();
        services.AddSingleton<CertificateRevocationGate>();
        services.AddScoped<DeviceAttestationPolicyService>();
        services.AddScoped<DomainPolicyAuditService>();
        services.AddScoped<OrderService>();
        services.AddSingleton<IChallengeValidator>(_validator);
        _provider = services.BuildServiceProvider();

        using (var scope = _provider.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
            db.Database.EnsureCreated();

            var account = new AcmeAccount
            {
                AccountId = "worker-stall-account",
                JwkJson = """{"kty":"RSA","n":"test","e":"AQAB"}""",
                JwkThumbprint = "worker-stall-thumbprint",
                Status = "valid",
                CreatedAt = DateTime.UtcNow
            };
            db.AcmeAccounts.Add(account);
            db.SaveChanges();

            // The stalling order is inserted first, so the sweep reaches it first.
            db.AcmeOrders.Add(ProcessingOrder(account, StallingDomain));
            db.AcmeOrders.Add(ProcessingOrder(account, NextDomain));
            db.SaveChanges();
        }

        _sut = new ChallengeValidationService(
            _provider.GetRequiredService<IServiceScopeFactory>(),
            NullLogger<ChallengeValidationService>.Instance,
            Options.Create(new ChallengeValidationOptions()));
    }

    public void Dispose()
    {
        _provider.Dispose();
        _connection.Dispose();
        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task OneValidatorThrowing_StillValidatesTheNextChallengeInTheSameSweep()
    {
        await _sut.ProcessPendingChallengesAsync(CancellationToken.None);

        // The sweep must reach the challenge after the one that threw.
        _validator.Domains.Should().Equal(StallingDomain, NextDomain);

        using var scope = _provider.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();

        (await db.AcmeAuthorizations.SingleAsync(a => a.IdentifierValue == NextDomain))
            .Status.Should().Be("valid");
        (await db.AcmeOrders.SingleAsync(o => o.IdentifiersJson.Contains(NextDomain)))
            .Status.Should().Be("ready");
    }

    [Fact]
    public async Task OneValidatorThrowing_LeavesThatChallengeProcessingForTheNextSweep()
    {
        // Transient by construction: the validator never answered, so nothing
        // says the client's response was wrong. RFC 8555 section 8.2 lets the
        // server retry, and the expiry guard ends it if it never stops throwing.
        await _sut.ProcessPendingChallengesAsync(CancellationToken.None);

        using var scope = _provider.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();

        var stalled = await db.AcmeChallenges
            .Include(c => c.Authorization)
            .SingleAsync(c => c.Authorization.IdentifierValue == StallingDomain);
        stalled.Status.Should().Be("processing");
        stalled.Authorization.Status.Should().Be("pending");
    }

    [Fact]
    public async Task Cancellation_StillEndsTheSweep()
    {
        // The per challenge catch must not swallow the stop signal, or the
        // worker would run through the whole list on shutdown.
        using var cts = new CancellationTokenSource();
        _validator.OnFirstCall = cts.Cancel;

        var act = () => _sut.ProcessPendingChallengesAsync(cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
        _validator.Domains.Should().HaveCount(1);
    }

    private static AcmeOrder ProcessingOrder(AcmeAccount account, string domain)
    {
        var now = DateTime.UtcNow;
        var expires = now.AddDays(7);
        return new AcmeOrder
        {
            OrderId = $"order-{domain}",
            Account = account,
            Status = "pending",
            TemplateId = "WebServer",
            IdentifiersJson = $$"""[{"type":"dns","value":"{{domain}}"}]""",
            CreatedAt = now,
            ExpiresAt = expires,
            Authorizations =
            {
                new AcmeAuthorization
                {
                    AuthorizationId = $"authz-{domain}",
                    IdentifierType = "dns",
                    IdentifierValue = domain,
                    Status = "pending",
                    CreatedAt = now,
                    ExpiresAt = expires,
                    Challenges =
                    {
                        new AcmeChallenge
                        {
                            ChallengeId = $"chal-{domain}",
                            Type = "http-01",
                            Token = "token",
                            Status = "processing"
                        }
                    }
                }
            }
        };
    }

    /// <summary>
    /// Stands in for the http-01 validator. The stalling domain throws the
    /// IOException a dying handshake produces; every other domain validates.
    /// Records the order it was asked in, which is the sweep order.
    /// </summary>
    private sealed class ThrowingValidator : IChallengeValidator
    {
        public List<string> Domains { get; } = new();
        public Action? OnFirstCall { get; set; }

        public string ChallengeType => "http-01";

        public Task<ChallengeValidationResult> ValidateAsync(
            ChallengeValidationContext context, CancellationToken cancellationToken = default)
        {
            Domains.Add(context.IdentifierValue);
            if (Domains.Count == 1)
                OnFirstCall?.Invoke();
            cancellationToken.ThrowIfCancellationRequested();

            if (context.IdentifierValue == StallingDomain)
                throw new IOException("Received an unexpected EOF or 0 bytes from the transport stream.");

            return Task.FromResult(ChallengeValidationResult.Success());
        }
    }
}

using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Certus.Core.Acme.Services;
using Certus.Core.Adcs;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Certus.Web.Tests;

/// <summary>
/// The dashboard revocation endpoint (issue #159): the happy path through
/// the mock CA and the in request resync, every refusal that must not reach
/// the CA (already revoked, not a certificate, bad reason, serial mismatch),
/// and the cross surface stamp that keeps the ACME revoke-cert contract
/// honest after a dashboard revoke. CA failure mapping lives in
/// <see cref="CertificateRevocationCaFailureTests"/> on its own factory.
/// </summary>
[Trait("Category", "Integration")]
[Collection("ACME Integration")]
public class CertificateRevocationIntegrationTests
{
    private readonly CertusWebApplicationFactory _factory;
    private readonly HttpClient _client;

    public CertificateRevocationIntegrationTests(CertusWebApplicationFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    private MockAdcsClient Adcs =>
        (MockAdcsClient)_factory.Services.GetRequiredService<IAdcsClient>();

    [Fact]
    public async Task Revoke_IssuedCertificate_RevokesAtCaAndResyncs()
    {
        var target = await IssueAndSyncAsync("revoke-happy.example.com");

        var response = await PostRevokeAsync(target.Id, reason: 4, target.Serial);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = JsonSerializer.Deserialize<JsonElement>(
            await response.Content.ReadAsStringAsync());

        body.GetProperty("outcome").GetString().Should().Be("revoked");
        body.GetProperty("resynced").GetBoolean().Should().BeTrue();

        // The certificate in the response is the resynced row: the CA's own
        // view, carrying the revocation and the chosen reason.
        var cert = body.GetProperty("certificate");
        cert.GetProperty("status").GetString().Should().Be("Revoked");
        cert.GetProperty("revokedReason").GetInt32().Should().Be(4);
        cert.GetProperty("revokedAt").ValueKind.Should().NotBe(JsonValueKind.Null);

        // The CA was asked to revoke exactly this serial.
        Adcs.RevokedSerials.Should().Contain(s =>
            SerialNumbers.NormalizedEquals(s, target.Serial));
    }

    [Fact]
    public async Task Revoke_AlreadyRevokedRow_Returns409WithoutCaCall()
    {
        // Seeded straight into the inventory as Revoked, so any CA call at
        // all would be a second revocation.
        var serial = "0dc0ffee00000001";
        var id = await SeedRowAsync(status: "Revoked", serial: serial);

        var response = await PostRevokeAsync(id, reason: 1, serial);

        response.StatusCode.Should().Be(HttpStatusCode.Conflict);
        (await ProblemTypeAsync(response)).Should().Be(
            "https://ducksinarow.dev/problems/certificate-already-revoked");
        Adcs.RevokedSerials.Should().NotContain(s =>
            SerialNumbers.NormalizedEquals(s, serial));
    }

    [Fact]
    public async Task Revoke_PendingRow_Returns409NotRevocable()
    {
        // A request table row: no certificate ever existed, nothing to revoke.
        var id = await SeedRowAsync(status: "Pending", serial: string.Empty);

        var response = await PostRevokeAsync(id, reason: 1, "AA");

        response.StatusCode.Should().Be(HttpStatusCode.Conflict);
        (await ProblemTypeAsync(response)).Should().Be(
            "https://ducksinarow.dev/problems/certificate-not-revocable");
    }

    [Theory]
    [InlineData(8)]   // Remove From CRL: un-revocation, never offered
    [InlineData(9)]   // Privilege Withdrawn: unprobed against ADCS
    [InlineData(42)]  // not a reason code at all
    [InlineData(-1)]
    public async Task Revoke_ReasonOutsidePermittedSet_Returns400WithoutCaCall(int reason)
    {
        var target = await IssueAndSyncAsync($"revoke-reason-{reason + 1}.example.com");

        var response = await PostRevokeAsync(target.Id, reason, target.Serial);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ProblemTypeAsync(response)).Should().Be(
            "https://ducksinarow.dev/problems/invalid-revocation-reason");
        Adcs.RevokedSerials.Should().NotContain(s =>
            SerialNumbers.NormalizedEquals(s, target.Serial));
    }

    [Fact]
    public async Task Revoke_SerialMismatch_Returns409WithoutCaCall()
    {
        var target = await IssueAndSyncAsync("revoke-mismatch.example.com");

        var response = await PostRevokeAsync(target.Id, reason: 1, "DEADBEEF");

        response.StatusCode.Should().Be(HttpStatusCode.Conflict);
        (await ProblemTypeAsync(response)).Should().Be(
            "https://ducksinarow.dev/problems/revocation-target-mismatch");
        Adcs.RevokedSerials.Should().NotContain(s =>
            SerialNumbers.NormalizedEquals(s, target.Serial));

        // Refused, so the row still reads Issued.
        var detail = await _client.GetAsync($"/api/certificates/{target.Id}");
        var body = JsonSerializer.Deserialize<JsonElement>(
            await detail.Content.ReadAsStringAsync());
        body.GetProperty("status").GetString().Should().Be("Issued");
    }

    [Fact]
    public async Task Revoke_MissingSerialInBody_Returns400()
    {
        var target = await IssueAndSyncAsync("revoke-noserial.example.com");

        var response = await _client.PostAsync(
            $"/api/certificates/{target.Id}/revoke",
            JsonContent(new { reason = 1 }));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Revoke_UnknownId_Returns404()
    {
        var response = await PostRevokeAsync(99_999_999, reason: 1, "AA");

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task Revoke_AcmeIssuedCertificate_StampsAcmeRecordSoRevokeCertAnswersAlreadyRevoked()
    {
        // An inventory row that is also an ACME certificate. The dashboard
        // revoke must stamp the ACME record, or a later ACME revoke-cert for
        // the same certificate would call the CA a second time instead of
        // answering alreadyRevoked (RFC 8555 §7.6).
        var target = await IssueAndSyncAsync("revoke-acme.example.com");
        var suffix = Guid.NewGuid().ToString("N");

        int acmeCertDbId;
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
            var acmeCert = new AcmeCertificate
            {
                CertificateId = $"revoke-test-{suffix}",
                Order = new AcmeOrder
                {
                    OrderId = $"revoke-test-order-{suffix}",
                    Account = new AcmeAccount
                    {
                        AccountId = $"revoke-test-acct-{suffix}",
                        JwkJson = "{}",
                        JwkThumbprint = $"revoke-test-thumb-{suffix}",
                    },
                    Status = "valid",
                    CertificateId = $"revoke-test-{suffix}",
                    TemplateId = "WebServer",
                    ExpiresAt = DateTime.UtcNow.AddDays(1),
                },
                CertificatePem = target.Pem,
                AdcsRequestId = target.RequestId,
                SerialNumber = target.Serial,
            };
            db.AcmeCertificates.Add(acmeCert);
            await db.SaveChangesAsync();
            acmeCertDbId = acmeCert.Id;
        }

        var response = await PostRevokeAsync(target.Id, reason: 1, target.Serial);
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var callsAfterDashboardRevoke = Adcs.RevokedSerials.Count(s =>
            SerialNumbers.NormalizedEquals(s, target.Serial));
        callsAfterDashboardRevoke.Should().Be(1);

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
            var stamped = await db.AcmeCertificates
                .Include(c => c.Order)
                .FirstAsync(c => c.Id == acmeCertDbId);

            stamped.RevokedAt.Should().NotBeNull();
            stamped.RevokedReason.Should().Be(1);

            // The ACME side now refuses from its own record, with no second
            // CA call.
            var orderService = scope.ServiceProvider.GetRequiredService<OrderService>();
            var outcome = await orderService.RevokeCertificateAsync(stamped, reason: 1);
            outcome.Should().Be(RevokeOutcome.AlreadyRevoked);
        }

        Adcs.RevokedSerials.Count(s => SerialNumbers.NormalizedEquals(s, target.Serial))
            .Should().Be(callsAfterDashboardRevoke);
    }

    [Fact]
    public async Task Revoke_RowWithoutCapabilityData_Returns403GuardrailWithoutCaCall()
    {
        // An issued row with no raw certificate and no parsed EKU or key
        // usage columns: the gate cannot verify the TLS capability, and
        // undetermined always refuses. The remedy sentence points at a
        // refresh because a sync backfills the raw blob.
        var serial = "0dc0ffee00000002";
        var id = await SeedRowAsync(status: "Issued", serial: serial);

        var response = await PostRevokeAsync(id, reason: 1, serial);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await ProblemTypeAsync(response)).Should().Be(
            "https://ducksinarow.dev/problems/revocation-blocked-by-guardrail");
        Adcs.RevokedSerials.Should().NotContain(s =>
            SerialNumbers.NormalizedEquals(s, serial));

        // The detail response carries the same reason for the disabled
        // button, from the same evaluator.
        var detail = await _client.GetAsync($"/api/certificates/{id}");
        var body = JsonSerializer.Deserialize<JsonElement>(
            await detail.Content.ReadAsStringAsync());
        body.GetProperty("revocationBlocked").GetString().Should().Be("guardrail");
        body.GetProperty("revocationBlockedDetail").GetString()
            .Should().Contain("Refresh the inventory");
    }

    [Fact]
    public async Task Revoke_SmartCardLogonCertificate_Returns403NamingTheUsage()
    {
        // A synced identity certificate: client auth next to smart card
        // logon. The ceiling refuses on the named dangerous usage, whatever
        // scope or provenance says, and the message tells the admin which
        // usage tripped it.
        var serial = "0dc0ffee00000003";
        var id = await SeedRowAsync(
            status: "Issued", serial: serial,
            ekuOids: "1.3.6.1.5.5.7.3.2, 1.3.6.1.4.1.311.20.2.2");

        var response = await PostRevokeAsync(id, reason: 4, serial);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await ProblemTypeAsync(response)).Should().Be(
            "https://ducksinarow.dev/problems/revocation-blocked-by-guardrail");
        var body = JsonSerializer.Deserialize<JsonElement>(
            await response.Content.ReadAsStringAsync());
        body.GetProperty("detail").GetString().Should().Contain("smart card logon");
        Adcs.RevokedSerials.Should().NotContain(s =>
            SerialNumbers.NormalizedEquals(s, serial));
    }

    [Fact]
    public async Task Revoke_MockIssuedTlsCertificate_StillRevokes()
    {
        // The gate must not break the ordinary path: a mock issued leaf now
        // carries server authentication EKU and a real key usage, passes the
        // ceiling from its stored raw certificate, and revokes as before.
        var target = await IssueAndSyncAsync("revoke-ceiling-pass.example.com");

        var response = await PostRevokeAsync(target.Id, reason: 0, target.Serial);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    private sealed record RevocationTarget(int Id, int RequestId, string Serial, string Pem);

    /// <summary>
    /// Issues a certificate through the mock CA, syncs the inventory, and
    /// returns the row id plus the serial in the X509 form the dashboard
    /// serves (the endpoint normalizes, so form differences must not matter).
    /// </summary>
    private async Task<RevocationTarget> IssueAndSyncAsync(string cn)
    {
        var submit = await Adcs.SubmitCertificateRequestAsync("WebServer", CreateCsr($"CN={cn}"));
        submit.Status.Should().Be(SubmitStatus.Issued);

        var issued = await Adcs.GetCertificateAsync(submit.RequestId);
        using var x509 = X509CertificateLoader.LoadCertificate(issued.CertificateDer!);
        var pem = new string(PemEncoding.Write("CERTIFICATE", issued.CertificateDer!));

        var sync = await _client.PostAsync("/api/certificates/sync", content: null);
        sync.StatusCode.Should().Be(HttpStatusCode.OK);

        var list = await _client.GetAsync($"/api/certificates?search={cn}");
        var listBody = JsonSerializer.Deserialize<JsonElement>(
            await list.Content.ReadAsStringAsync());
        var row = listBody.GetProperty("items").EnumerateArray()
            .Single(i => i.GetProperty("subject").GetString()!.Contains(cn));

        return new RevocationTarget(
            row.GetProperty("id").GetInt32(), submit.RequestId, x509.SerialNumber, pem);
    }

    /// <summary>
    /// Inserts an inventory row directly, for states the mock CA cannot
    /// produce on demand (already revoked, still pending). The sync never
    /// deletes rows it does not see, so a seeded row survives other tests'
    /// syncs in this shared collection.
    /// </summary>
    private async Task<int> SeedRowAsync(
        string status, string serial, string? ekuOids = null, int? keyUsage = null)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        var entity = new SyncedCertificate
        {
            // Far above anything the mock CA's counter will reach, so a sync
            // upsert can never collide with a seeded row.
            RequestId = Random.Shared.Next(80_000_000, 90_000_000),
            SerialNumber = serial,
            Subject = $"CN=revoke-seeded-{Guid.NewGuid():N}",
            TemplateName = "WebServer",
            Status = status,
            RequestDate = DateTime.UtcNow,
            NotBefore = DateTime.UtcNow,
            NotAfter = DateTime.UtcNow.AddYears(1),
            RevokedAt = status == "Revoked" ? DateTime.UtcNow : null,
            RevokedReason = status == "Revoked" ? 0 : null,
            // Capability columns for the eligibility gate. A seeded row has
            // no RawCertificate, so the gate reads exactly these.
            ExtendedKeyUsageOids = ekuOids,
            KeyUsage = keyUsage,
        };
        db.SyncedCertificates.Add(entity);
        await db.SaveChangesAsync();
        return entity.Id;
    }

    private Task<HttpResponseMessage> PostRevokeAsync(int id, int reason, string serialNumber)
        => _client.PostAsync(
            $"/api/certificates/{id}/revoke",
            JsonContent(new { reason, serialNumber }));

    private static StringContent JsonContent(object payload) => new(
        JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

    private static async Task<string?> ProblemTypeAsync(HttpResponseMessage response)
    {
        response.Content.Headers.ContentType?.MediaType.Should().Be("application/problem+json");
        var body = JsonSerializer.Deserialize<JsonElement>(
            await response.Content.ReadAsStringAsync());
        return body.GetProperty("type").GetString();
    }

    private static byte[] CreateCsr(string subject)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            new X500DistinguishedName(subject), key,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSigningRequest();
    }
}

/// <summary>
/// CA failure mapping for the revocation endpoint, on a factory whose
/// IAdcsClient issues and queries through the normal mock but fails the
/// revoke call in a configurable way: the CA being unreachable and the CA
/// denying the revoke ACL surface as the existing 503 problem types with the
/// row untouched, and an unanticipated CA refusal surfaces as 500 ca-error.
/// </summary>
[Trait("Category", "Integration")]
public class CertificateRevocationCaFailureTests
    : IClassFixture<CertificateRevocationCaFailureTests.RevokeFailingCaFactory>
{
    private readonly RevokeFailingCaFactory _factory;
    private readonly HttpClient _client;

    public CertificateRevocationCaFailureTests(RevokeFailingCaFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task Revoke_CaUnavailable_Returns503AndLeavesRowUntouched()
    {
        var (id, serial) = await IssueAndSyncAsync("revoke-ca-down.example.com");
        _factory.Client.RevokeFailure = () => new CaUnavailableException("simulated CA outage");

        var response = await PostRevokeAsync(id, 1, serial);

        response.StatusCode.Should().Be(HttpStatusCode.ServiceUnavailable);
        (await ProblemTypeAsync(response)).Should().Be(
            "https://ducksinarow.dev/problems/ca-unavailable");
        await AssertStatusAsync(id, "Issued");
    }

    [Fact]
    public async Task Revoke_CaAccessDenied_Returns503AndLeavesRowUntouched()
    {
        var (id, serial) = await IssueAndSyncAsync("revoke-ca-denied.example.com");
        _factory.Client.RevokeFailure = () => new CaAccessDeniedException(
            CaAccessDeniedException.RevokePermissionMessage,
            new UnauthorizedAccessException("simulated E_ACCESSDENIED"));

        var response = await PostRevokeAsync(id, 1, serial);

        response.StatusCode.Should().Be(HttpStatusCode.ServiceUnavailable);
        (await ProblemTypeAsync(response)).Should().Be(
            "https://ducksinarow.dev/problems/ca-access-denied");
        await AssertStatusAsync(id, "Issued");
    }

    [Fact]
    public async Task Revoke_UnexpectedCaFailure_Returns500CaError()
    {
        var (id, serial) = await IssueAndSyncAsync("revoke-ca-refused.example.com");
        _factory.Client.RevokeFailure = () =>
            new InvalidOperationException("Failed to revoke certificate: simulated refusal");

        var response = await PostRevokeAsync(id, 1, serial);

        response.StatusCode.Should().Be(HttpStatusCode.InternalServerError);
        (await ProblemTypeAsync(response)).Should().Be(
            "https://ducksinarow.dev/problems/ca-error");
        await AssertStatusAsync(id, "Issued");
    }

    [Fact]
    public async Task Revoke_ResyncFails_StillRecordsRevocationAndRefusesASecondCaCall()
    {
        // The failure the whole floor stamp exists for. The CA revokes, then
        // the follow up inventory sync cannot run. Without a local record the
        // row would still read Issued, the page would still offer Revoke, and
        // a retry would send the CA a second revocation for a certificate it
        // has already revoked, which the acceptance criteria forbid.
        var (id, serial) = await IssueAndSyncAsync("revoke-resync-down.example.com");
        var before = _factory.Client.Inner.RevokedSerials.Count(s =>
            SerialNumbers.NormalizedEquals(s, serial));

        // Revoking still works; only the query the sync depends on is down.
        _factory.Client.QueryFailure = () => new CaUnavailableException("simulated CA outage");

        var response = await PostRevokeAsync(id, 5, serial);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = JsonSerializer.Deserialize<JsonElement>(
            await response.Content.ReadAsStringAsync());

        // Honest about the resync, and still reporting the revocation.
        body.GetProperty("resynced").GetBoolean().Should().BeFalse();
        var cert = body.GetProperty("certificate");
        cert.GetProperty("status").GetString().Should().Be("Revoked");
        cert.GetProperty("revokedReason").GetInt32().Should().Be(5);

        _factory.Client.Inner.RevokedSerials.Count(s =>
            SerialNumbers.NormalizedEquals(s, serial)).Should().Be(before + 1);

        // The retry an admin makes when the page looks wrong: refused locally,
        // with no second trip to the CA.
        var retry = await PostRevokeAsync(id, 5, serial);

        retry.StatusCode.Should().Be(HttpStatusCode.Conflict);
        (await ProblemTypeAsync(retry)).Should().Be(
            "https://ducksinarow.dev/problems/certificate-already-revoked");
        _factory.Client.Inner.RevokedSerials.Count(s =>
            SerialNumbers.NormalizedEquals(s, serial)).Should().Be(before + 1);
    }

    private async Task<(int Id, string Serial)> IssueAndSyncAsync(string cn)
    {
        _factory.Client.RevokeFailure = null;
        _factory.Client.QueryFailure = null;

        var inner = _factory.Client.Inner;
        var submit = await inner.SubmitCertificateRequestAsync("WebServer", CreateCsr($"CN={cn}"));
        var issued = await inner.GetCertificateAsync(submit.RequestId);
        using var x509 = X509CertificateLoader.LoadCertificate(issued.CertificateDer!);

        var sync = await _client.PostAsync("/api/certificates/sync", content: null);
        sync.StatusCode.Should().Be(HttpStatusCode.OK);

        var list = await _client.GetAsync($"/api/certificates?search={cn}");
        var listBody = JsonSerializer.Deserialize<JsonElement>(
            await list.Content.ReadAsStringAsync());
        var row = listBody.GetProperty("items").EnumerateArray()
            .Single(i => i.GetProperty("subject").GetString()!.Contains(cn));

        return (row.GetProperty("id").GetInt32(), x509.SerialNumber);
    }

    private Task<HttpResponseMessage> PostRevokeAsync(int id, int reason, string serialNumber)
        => _client.PostAsync(
            $"/api/certificates/{id}/revoke",
            new StringContent(
                JsonSerializer.Serialize(new { reason, serialNumber }),
                Encoding.UTF8, "application/json"));

    private async Task AssertStatusAsync(int id, string expected)
    {
        var detail = await _client.GetAsync($"/api/certificates/{id}");
        var body = JsonSerializer.Deserialize<JsonElement>(
            await detail.Content.ReadAsStringAsync());
        body.GetProperty("status").GetString().Should().Be(expected);
    }

    private static async Task<string?> ProblemTypeAsync(HttpResponseMessage response)
    {
        var body = JsonSerializer.Deserialize<JsonElement>(
            await response.Content.ReadAsStringAsync());
        return body.GetProperty("type").GetString();
    }

    private static byte[] CreateCsr(string subject)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            new X500DistinguishedName(subject), key,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSigningRequest();
    }

    /// <summary>
    /// Factory whose IAdcsClient delegates to a real MockAdcsClient except
    /// for revocation, which throws whatever <see cref="RevokeFailingAdcsClient.RevokeFailure"/>
    /// says. Lets a certificate exist in the inventory while the revoke call
    /// alone fails, which no all failing stub can arrange.
    /// </summary>
    public sealed class RevokeFailingCaFactory : CertusWebApplicationFactory
    {
        public RevokeFailingAdcsClient Client { get; } = new();

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);

            builder.ConfigureServices(services =>
            {
                var existing = services.SingleOrDefault(d => d.ServiceType == typeof(IAdcsClient));
                if (existing != null)
                    services.Remove(existing);

                services.AddSingleton<IAdcsClient>(Client);
            });
        }
    }

    public sealed class RevokeFailingAdcsClient : IAdcsClient
    {
        public MockAdcsClient Inner { get; } = new();

        /// <summary>The failure the next revoke call throws; null delegates to the mock.</summary>
        public Func<Exception>? RevokeFailure { get; set; }

        /// <summary>
        /// The failure the certificate query throws; null delegates to the
        /// mock. Set on its own it takes the inventory sync down while
        /// revocation still works, which is the split the resync failure test
        /// needs and no all failing stub can produce.
        /// </summary>
        public Func<Exception>? QueryFailure { get; set; }

        public Task<CaInfo> GetCaInfoAsync(CancellationToken cancellationToken = default)
            => Inner.GetCaInfoAsync(cancellationToken);

        public Task<IReadOnlyList<TemplateInfo>> GetTemplatesAsync(CancellationToken cancellationToken = default)
            => Inner.GetTemplatesAsync(cancellationToken);

        public Task<IReadOnlyList<byte[]>> GetCaCertificateChainAsync(CancellationToken cancellationToken = default)
            => Inner.GetCaCertificateChainAsync(cancellationToken);

        public Task<SubmitResult> SubmitCertificateRequestAsync(
            string templateName, byte[] csrDer, CancellationToken cancellationToken = default)
            => Inner.SubmitCertificateRequestAsync(templateName, csrDer, cancellationToken);

        public Task<CertificateResult> GetCertificateAsync(
            int requestId, CancellationToken cancellationToken = default)
            => Inner.GetCertificateAsync(requestId, cancellationToken);

        public Task<IReadOnlyList<CertificateInfo>> QueryCertificatesAsync(
            CertificateQuery query, CancellationToken cancellationToken = default)
            => QueryFailure != null
                ? Task.FromException<IReadOnlyList<CertificateInfo>>(QueryFailure())
                : Inner.QueryCertificatesAsync(query, cancellationToken);

        public Task<CaRequestStatus?> GetRequestStatusAsync(
            int requestId, CancellationToken cancellationToken = default)
            => Inner.GetRequestStatusAsync(requestId, cancellationToken);

        public Task RevokeCertificateAsync(
            string serialNumber, int reason, CancellationToken cancellationToken = default)
            => RevokeFailure != null
                ? Task.FromException(RevokeFailure())
                : Inner.RevokeCertificateAsync(serialNumber, reason, cancellationToken);
    }
}

/// <summary>
/// The race issue #203 closes: two revoke requests for the same certificate
/// in flight at once. The factory's CA parks the first revoke call until the
/// test releases it, which holds the winner inside the CA call while the
/// second request arrives; the per serial gate must park that second request
/// short of the CA, so after release the winner reports revoked, the loser is
/// refused as already revoked, and the CA saw exactly one revocation. Before
/// the gate both requests passed the guards and the call count reached two.
/// </summary>
[Trait("Category", "Integration")]
public class CertificateRevocationRaceTests
    : IClassFixture<CertificateRevocationRaceTests.RevokeRaceCaFactory>
{
    private readonly RevokeRaceCaFactory _factory;
    private readonly HttpClient _client;

    public CertificateRevocationRaceTests(RevokeRaceCaFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task Revoke_TwoSimultaneousRequests_OnlyOneReachesTheCa()
    {
        var stub = _factory.Client;
        var (id, serial) = await IssueAndSyncAsync("revoke-race.example.com");

        try
        {
            // The winner: enters the CA call and parks there, holding the per
            // serial gate for the duration.
            var first = PostRevokeAsync(id, reason: 4, serial);
            await stub.FirstRevokeEntered.WaitAsync(TimeSpan.FromSeconds(10));

            // The loser: must wait at the gate, short of the CA. The delay
            // only gives a regression time to show; with the gate in place
            // the second request cannot reach the stub while the winner is
            // parked, so this assert cannot flake.
            var second = PostRevokeAsync(id, reason: 4, serial);
            await Task.Delay(250);
            stub.RevokeCalls.Should().Be(1,
                "the gate must hold the second request short of the CA");

            stub.ReleaseRevokes();

            var responses = await Task.WhenAll(first, second)
                .WaitAsync(TimeSpan.FromSeconds(30));

            // Deterministic roles: the first request held the gate before the
            // second was posted.
            var winner = responses[0];
            var loser = responses[1];

            winner.StatusCode.Should().Be(HttpStatusCode.OK);
            var body = JsonSerializer.Deserialize<JsonElement>(
                await winner.Content.ReadAsStringAsync());
            body.GetProperty("outcome").GetString().Should().Be("revoked");

            loser.StatusCode.Should().Be(HttpStatusCode.Conflict);
            (await ProblemTypeAsync(loser)).Should().Be(
                "https://ducksinarow.dev/problems/certificate-already-revoked");

            stub.RevokeCalls.Should().Be(1);
            stub.Inner.RevokedSerials.Count(s =>
                SerialNumbers.NormalizedEquals(s, serial)).Should().Be(1);
        }
        finally
        {
            // A failing assert must not leave a server request parked on the
            // release source.
            stub.ReleaseRevokes();
        }
    }

    private async Task<(int Id, string Serial)> IssueAndSyncAsync(string cn)
    {
        var inner = _factory.Client.Inner;
        var submit = await inner.SubmitCertificateRequestAsync("WebServer", CreateCsr($"CN={cn}"));
        var issued = await inner.GetCertificateAsync(submit.RequestId);
        using var x509 = X509CertificateLoader.LoadCertificate(issued.CertificateDer!);

        var sync = await _client.PostAsync("/api/certificates/sync", content: null);
        sync.StatusCode.Should().Be(HttpStatusCode.OK);

        var list = await _client.GetAsync($"/api/certificates?search={cn}");
        var listBody = JsonSerializer.Deserialize<JsonElement>(
            await list.Content.ReadAsStringAsync());
        var row = listBody.GetProperty("items").EnumerateArray()
            .Single(i => i.GetProperty("subject").GetString()!.Contains(cn));

        return (row.GetProperty("id").GetInt32(), x509.SerialNumber);
    }

    private Task<HttpResponseMessage> PostRevokeAsync(int id, int reason, string serialNumber)
        => _client.PostAsync(
            $"/api/certificates/{id}/revoke",
            new StringContent(
                JsonSerializer.Serialize(new { reason, serialNumber }),
                Encoding.UTF8, "application/json"));

    private static async Task<string?> ProblemTypeAsync(HttpResponseMessage response)
    {
        var body = JsonSerializer.Deserialize<JsonElement>(
            await response.Content.ReadAsStringAsync());
        return body.GetProperty("type").GetString();
    }

    private static byte[] CreateCsr(string subject)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            new X500DistinguishedName(subject), key,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSigningRequest();
    }

    /// <summary>
    /// Factory whose IAdcsClient is the shared <see cref="BlockingRevokeAdcsClient"/>
    /// parking stub, so the test can hold one request inside the CA call while a
    /// second arrives. That is the only way to make the race deterministic.
    /// </summary>
    public sealed class RevokeRaceCaFactory : CertusWebApplicationFactory
    {
        public BlockingRevokeAdcsClient Client { get; } = new();

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);

            builder.ConfigureServices(services =>
            {
                var existing = services.SingleOrDefault(d => d.ServiceType == typeof(IAdcsClient));
                if (existing != null)
                    services.Remove(existing);

                services.AddSingleton<IAdcsClient>(Client);
            });
        }
    }
}

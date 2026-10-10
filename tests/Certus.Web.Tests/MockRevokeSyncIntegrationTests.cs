using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Certus.Core.Acme.Services;
using Certus.Core.Adcs;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Microsoft.Extensions.DependencyInjection;

namespace Certus.Web.Tests;

/// <summary>
/// End to end cover for the revoke visibility chain: a certificate issued
/// and revoked through the mock CA must appear in the inventory and the
/// activity feed as revoked with its real name after a sync. Exercises the
/// mock revoke flip, the sync upsert, and the dashboard feed together. Every
/// row here is issued, and the mock names an issued row from its own signed
/// certificate, so the empty subject fallbacks (first SAN, update guard, ACME
/// store backfill) are covered by the unit tests in AdcsColumnMappingTests and
/// CertificateSyncServiceTests instead. A request row the mock has not signed
/// does come back with an empty subject, which is what those fallbacks are for.
/// </summary>
[Trait("Category", "Integration")]
[Collection("ACME Integration")]
public class MockRevokeSyncIntegrationTests
{
    private readonly CertusWebApplicationFactory _factory;
    private readonly HttpClient _client;

    public MockRevokeSyncIntegrationTests(CertusWebApplicationFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task RevokedMockCertificate_ShowsNameInInventoryAndActivity()
    {
        // Issue a certificate straight through the mock CA.
        var adcs = (MockAdcsClient)_factory.Services.GetRequiredService<IAdcsClient>();
        var submit = await adcs.SubmitCertificateRequestAsync(
            "WebServer", CreateCsr("CN=mock-revoke.example.com"));
        submit.Status.Should().Be(SubmitStatus.Issued);

        // Revoke it by the X509 serial form (uppercase, possibly 00 padded),
        // the way the ACME revoke endpoint supplies it.
        var issued = await adcs.GetCertificateAsync(submit.RequestId);
        using var x509 = X509CertificateLoader.LoadCertificate(issued.CertificateDer!);
        await adcs.RevokeCertificateAsync(x509.SerialNumber, reason: 0);

        // Pull the inventory from the CA into the local database.
        var sync = await _client.PostAsync("/api/certificates/sync", content: null);
        sync.StatusCode.Should().Be(HttpStatusCode.OK);

        // Inventory: the row is revoked and keeps its name.
        var list = await _client.GetAsync("/api/certificates?search=mock-revoke");
        list.StatusCode.Should().Be(HttpStatusCode.OK);
        var listBody = JsonSerializer.Deserialize<JsonElement>(
            await list.Content.ReadAsStringAsync());
        var items = listBody.GetProperty("items").EnumerateArray().ToList();
        items.Should().Contain(i =>
            i.GetProperty("subject").GetString()!.Contains("mock-revoke.example.com") &&
            i.GetProperty("status").GetString() == "Revoked");

        // Activity feed: a revoked entry with the real name, not "Unknown".
        var activity = await _client.GetAsync("/api/dashboard/activity?take=100");
        activity.StatusCode.Should().Be(HttpStatusCode.OK);
        var activityBody = JsonSerializer.Deserialize<JsonElement>(
            await activity.Content.ReadAsStringAsync());
        activityBody.EnumerateArray().Should().Contain(i =>
            i.GetProperty("type").GetString() == "revoked" &&
            i.GetProperty("cn").GetString() == "mock-revoke.example.com");
    }

    [Fact]
    public async Task CommaBearingCommonName_SurvivesTheWholeChainToTheDashboard()
    {
        // The end to end half of issue #240. The mock now renders a subject the
        // way X509Certificate2 does, so a comma inside a common name reaches the
        // dashboard wrapped in quotes rather than escaped with a backslash. That
        // is the spelling a live certificate authority produces, and until the
        // mock spoke it no test could carry one of these through the real HTTP
        // surface: the sync's writer, the inventory search, and the activity
        // feed's common name reader all see it here for the first time.
        //
        // A comma is legal inside a common name, and on a template with enrollee
        // supplies subject the requester chooses it, which is what made this the
        // blast radius of both reader spoofs (issues #231 and #238).
        const string commonName = "corp, O=Trusted Corp";

        var adcs = (MockAdcsClient)_factory.Services.GetRequiredService<IAdcsClient>();
        var submit = await adcs.SubmitCertificateRequestAsync(
            "WebServer", CreateCsr($"CN=\"{commonName}\", O=Real Org"));
        submit.Status.Should().Be(SubmitStatus.Issued);

        // Revoked so the row reaches the activity feed, which is where the
        // common name reader runs. The feed's issued entries come from the ACME
        // store and carry the order identifier rather than the subject, so a
        // revoked row is the one that exercises ExtractCn over a stored subject.
        var issued = await adcs.GetCertificateAsync(submit.RequestId);
        using var x509 = X509CertificateLoader.LoadCertificate(issued.CertificateDer!);
        await adcs.RevokeCertificateAsync(x509.SerialNumber, reason: 0);

        var sync = await _client.PostAsync("/api/certificates/sync", content: null);
        sync.StatusCode.Should().Be(HttpStatusCode.OK);

        // Inventory: the stored subject is the quoted form, not the escaped one.
        var list = await _client.GetAsync("/api/certificates?search=Trusted%20Corp");
        list.StatusCode.Should().Be(HttpStatusCode.OK);
        var listBody = JsonSerializer.Deserialize<JsonElement>(
            await list.Content.ReadAsStringAsync());
        var subjects = listBody.GetProperty("items").EnumerateArray()
            .Select(i => i.GetProperty("subject").GetString())
            .ToList();
        subjects.Should().Contain($"CN=\"{commonName}\", O=Real Org");
        subjects.Should().NotContain(s => s != null && s.Contains("\\,"));

        // Activity feed: the reader returns the whole name rather than the
        // fragment a stop at the first comma would give.
        var activity = await _client.GetAsync("/api/dashboard/activity?take=100");
        activity.StatusCode.Should().Be(HttpStatusCode.OK);
        var activityBody = JsonSerializer.Deserialize<JsonElement>(
            await activity.Content.ReadAsStringAsync());
        activityBody.EnumerateArray().Should().Contain(i =>
            i.GetProperty("type").GetString() == "revoked" &&
            i.GetProperty("cn").GetString() == commonName);
    }

    [Fact]
    public async Task CommonNameEndingInABackslash_SurvivesTheWholeChainToTheDashboard()
    {
        // The end to end half of issue #296, and the same chain the comma bearing
        // name above walks, for the shape that broke differently.
        //
        // Windows renders a value ending in a backslash bare, so the backslash
        // lands immediately in front of the ", " that starts the next component.
        // A reader that treats a backslash as an escape steps over that separator
        // and swallows the rest of the subject into the name, so this certificate
        // reached the dashboard as "trailing-slash.example.com, O=Real Org", a
        // name it does not carry. On a template with enrollee supplies subject the
        // requester chooses both the value and the order, so the requester chooses
        // this.
        //
        // The name is built by relative distinguished name rather than parsed from
        // a string, so the backslash the CA signs is exactly the one asked for.
        const string commonName = "trailing-slash.example.com\\";

        var name = new X500DistinguishedNameBuilder();
        name.AddCommonName(commonName);
        name.AddOrganizationName("Real Org");

        var adcs = (MockAdcsClient)_factory.Services.GetRequiredService<IAdcsClient>();
        var submit = await adcs.SubmitCertificateRequestAsync("WebServer", CreateCsr(name.Build()));
        submit.Status.Should().Be(SubmitStatus.Issued);

        // Revoked for the same reason as above: the activity feed's issued entries
        // carry the order identifier, so a revoked row is the one that runs the
        // common name reader over a stored subject.
        var issued = await adcs.GetCertificateAsync(submit.RequestId);
        using var x509 = X509CertificateLoader.LoadCertificate(issued.CertificateDer!);
        await adcs.RevokeCertificateAsync(x509.SerialNumber, reason: 0);

        var sync = await _client.PostAsync("/api/certificates/sync", content: null);
        sync.StatusCode.Should().Be(HttpStatusCode.OK);

        // Inventory: the stored subject keeps the backslash bare, unquoted.
        var list = await _client.GetAsync("/api/certificates?search=trailing-slash");
        list.StatusCode.Should().Be(HttpStatusCode.OK);
        var listBody = JsonSerializer.Deserialize<JsonElement>(
            await list.Content.ReadAsStringAsync());
        var subjects = listBody.GetProperty("items").EnumerateArray()
            .Select(i => i.GetProperty("subject").GetString())
            .ToList();
        subjects.Should().Contain($"CN={commonName}, O=Real Org");

        // Activity feed: the reader stops at the real component boundary rather
        // than reading on into the organisation name.
        var activity = await _client.GetAsync("/api/dashboard/activity?take=100");
        activity.StatusCode.Should().Be(HttpStatusCode.OK);
        var activityBody = JsonSerializer.Deserialize<JsonElement>(
            await activity.Content.ReadAsStringAsync());
        var entries = activityBody.EnumerateArray()
            .Where(i => i.GetProperty("type").GetString() == "revoked")
            .Select(i => i.GetProperty("cn").GetString())
            .ToList();
        entries.Should().Contain(commonName);
        entries.Should().NotContain("trailing-slash.example.com, O=Real Org");
    }

    [Fact]
    public async Task HoldReleasedAtTheCa_StopsTheRenewNowSignalOnTheNextSync()
    {
        // The end to end half of issue #375, and the other direction of the
        // chain the tests above walk. A certificate revoked with reason 6
        // (certificateHold) and later released kept answering a renew now
        // window on renewalInfo for the rest of its life, because nothing ever
        // cleared AcmeCertificate.RevokedAt.
        //
        // The mock is never asked to revoke here, because it has no release of
        // its own and the sync could not tell the difference if it had: all the
        // sync ever sees is the CA's answer now, and "issued" is that answer
        // once a hold is lifted. What the stamp below stands for is the
        // revocation that preceded it. The conditions under which the repair
        // fires, and the five under which it must not, are unit covered in
        // CertificateSyncServiceTests.
        var adcs = (MockAdcsClient)_factory.Services.GetRequiredService<IAdcsClient>();
        var submit = await adcs.SubmitCertificateRequestAsync(
            "WebServer", CreateCsr("CN=held-then-released.example.com"));
        submit.Status.Should().Be(SubmitStatus.Issued);

        var issued = await adcs.GetCertificateAsync(submit.RequestId);
        using var leaf = X509CertificateLoader.LoadCertificate(issued.CertificateDer!);
        var ariId = AriCertificateId.FromCertificate(leaf);
        ariId.Should().NotBeNull("the mock stamps an AKI, which is what makes a leaf ARI addressable");

        var suffix = Guid.NewGuid().ToString("N")[..8];
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
            var account = new AcmeAccount
            {
                AccountId = "hold-acct-" + suffix,
                JwkJson = """{"kty":"RSA","n":"test","e":"AQAB"}""",
                JwkThumbprint = "hold-thumb-" + suffix,
                Status = "valid",
            };
            db.AcmeAccounts.Add(account);
            await db.SaveChangesAsync();

            var order = new AcmeOrder
            {
                OrderId = "hold-order-" + suffix,
                AccountId = account.Id,
                Status = "valid",
                TemplateId = "WebServer",
                IdentifiersJson = """[{"type":"dns","value":"held-then-released.example.com"}]""",
                ExpiresAt = DateTime.UtcNow.AddDays(7),
                CertificateId = "hold-cert-" + suffix,
            };
            db.AcmeOrders.Add(order);
            await db.SaveChangesAsync();

            db.AcmeCertificates.Add(new AcmeCertificate
            {
                CertificateId = "hold-cert-" + suffix,
                OrderId = order.Id,
                CertificatePem = leaf.ExportCertificatePem(),
                AdcsRequestId = submit.RequestId,
                SerialNumber = leaf.SerialNumber,
                IssuedAt = DateTime.UtcNow,
                RevokedAt = DateTime.UtcNow.AddDays(-2),
                RevokedReason = 6,
            });
            await db.SaveChangesAsync();
        }

        // Before: the stamp alone drives the answer, so the window has already
        // closed. Asserted rather than assumed, or the assertion after the sync
        // would pass on a build where nothing was ever wrong.
        var before = await ReadRenewalWindowEndAsync(ariId!);
        before.Should().BeBefore(DateTimeOffset.UtcNow, "the stamped row must read as renew now first");

        var sync = await _client.PostAsync("/api/certificates/sync", content: null);
        sync.StatusCode.Should().Be(HttpStatusCode.OK);

        // After: the CA reported the certificate issued, so the stamp is no
        // longer its answer and the ordinary window is back.
        var after = await ReadRenewalWindowEndAsync(ariId!);
        after.Should().BeAfter(DateTimeOffset.UtcNow, "a released certificate renews on the normal schedule");
    }

    private async Task<DateTimeOffset> ReadRenewalWindowEndAsync(string ariId)
    {
        var response = await _client.GetAsync($"/acme/WebServer/renewalInfo/{ariId}");
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = JsonSerializer.Deserialize<JsonElement>(
            await response.Content.ReadAsStringAsync());
        return DateTimeOffset.Parse(
            body.GetProperty("suggestedWindow").GetProperty("end").GetString()!,
            CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
    }

    private static byte[] CreateCsr(string subject) =>
        CreateCsr(new X500DistinguishedName(subject));

    private static byte[] CreateCsr(X500DistinguishedName subject)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSigningRequest();
    }
}

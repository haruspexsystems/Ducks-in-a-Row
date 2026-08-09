using System.Net;
using System.Text;
using System.Text.Json;
using Certus.Web.Authentication;

namespace Certus.Web.Tests;

/// <summary>
/// Verification matrix for issue #27 (SEC-F1, SEC-F2, SEC-G1): the dashboard
/// and setup APIs require an authenticated admin, the public surface (ACME,
/// /health, reduced setup status, SPA shell) stays anonymous, mutating /api
/// requests require the CSRF header, setup completion locks, and unknown /api
/// routes never fall back to index.html.
/// </summary>
[Trait("Category", "Integration")]
public class AuthIntegrationTests : IClassFixture<AuthWebApplicationFactory>
{
    private readonly AuthWebApplicationFactory _factory;

    public AuthIntegrationTests(AuthWebApplicationFactory factory)
    {
        _factory = factory;
    }

    private HttpClient CreateClient(string? user = null, bool csrf = false)
    {
        var client = _factory.CreateClient();
        if (user != null)
            client.DefaultRequestHeaders.Add(TestAuthHandler.UserHeader, user);
        if (csrf)
            client.DefaultRequestHeaders.Add(CertusPolicies.CsrfHeaderName, "1");
        return client;
    }

    private static StringContent JsonContent(object payload) => new(
        JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

    private static async Task<JsonElement> ParseJsonAsync(HttpResponseMessage response)
    {
        var json = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<JsonElement>(json);
    }

    // ── Deny by default ─────────────────────────────────────────────────

    [Fact]
    public async Task Anonymous_Certificates_Returns401()
    {
        // The regression test for issue #27: this returned 200 with the full
        // CA inventory before authentication was wired.
        var response = await CreateClient().GetAsync("/api/certificates");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Anonymous_AlertsConfig_Returns401()
    {
        var response = await CreateClient().GetAsync("/api/alerts/config");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Admin_Certificates_Returns200()
    {
        var response = await CreateClient(TestAuthHandler.AdminUser).GetAsync("/api/certificates");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task AuthenticatedNonAdmin_Certificates_Returns403()
    {
        var response = await CreateClient("alice").GetAsync("/api/certificates");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    // ── Public carve-outs ───────────────────────────────────────────────

    [Fact]
    public async Task Anonymous_AcmeDirectory_Returns200()
    {
        // The crown-jewel guard: ACME must stay anonymous (JWS-authenticated).
        var response = await CreateClient().GetAsync("/acme/WebServer/directory");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Anonymous_Health_Returns200()
    {
        var response = await CreateClient().GetAsync("/health");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Anonymous_SetupStatus_Returns200WithBooleanOnly()
    {
        var response = await CreateClient().GetAsync("/api/setup/status");

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        // SEC-F2: anonymous status must expose nothing beyond the boolean.
        var body = await ParseJsonAsync(response);
        body.TryGetProperty("setupCompleted", out _).Should().BeTrue();
        body.TryGetProperty("caConnectionString", out _).Should().BeFalse();
        body.TryGetProperty("enabledTemplates", out _).Should().BeFalse();
        body.TryGetProperty("externalUrl", out _).Should().BeFalse();
    }

    // ── Setup config split ──────────────────────────────────────────────

    [Fact]
    public async Task Anonymous_SetupConfig_Returns401()
    {
        var response = await CreateClient().GetAsync("/api/setup/config");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Anonymous_TlsCertificateProvisioning_Returns401()
    {
        // The wizard's certificate enrollment mutates the machine store and
        // restarts the service; it must sit behind the same admin-only
        // policy as the rest of the setup API.
        var response = await CreateClient(csrf: true).PostAsync(
            "/api/setup/tls-certificate",
            JsonContent(new { caConnectionString = "ca\\CA", templateName = "WebServer", externalUrl = "https://x:5001" }));

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Admin_SetupConfig_Returns200WithFullDetail()
    {
        var response = await CreateClient(TestAuthHandler.AdminUser).GetAsync("/api/setup/config");

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        body.TryGetProperty("setupCompleted", out _).Should().BeTrue();
        body.TryGetProperty("caConnectionString", out _).Should().BeTrue();
        body.TryGetProperty("enabledTemplates", out _).Should().BeTrue();
        body.TryGetProperty("externalUrl", out _).Should().BeTrue();
    }

    // ── CSRF guard and setup completion lock ────────────────────────────

    [Fact]
    public async Task CompleteSetup_CsrfThenAuthThenLock()
    {
        var payload = new
        {
            caConnectionString = "ca.example.com\\Example-CA",
            enabledTemplates = new[] { "WebServer" },
            externalUrl = "https://certus.example.com",
        };

        // Admin without the CSRF header: blocked by the header guard.
        var noCsrf = await CreateClient(TestAuthHandler.AdminUser)
            .PostAsync("/api/setup/complete", JsonContent(payload));
        noCsrf.StatusCode.Should().Be(HttpStatusCode.Forbidden);

        // CSRF header but anonymous: blocked by the fallback policy.
        var anonymous = await CreateClient(csrf: true)
            .PostAsync("/api/setup/complete", JsonContent(payload));
        anonymous.StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        // Admin with the header: completes setup.
        var admin = CreateClient(TestAuthHandler.AdminUser, csrf: true);
        var completed = await admin.PostAsync("/api/setup/complete", JsonContent(payload));
        completed.StatusCode.Should().Be(HttpStatusCode.OK);

        // Second completion: locked (SEC-G1).
        var locked = await admin.PostAsync("/api/setup/complete", JsonContent(payload));
        locked.StatusCode.Should().Be(HttpStatusCode.Conflict);
    }

    // ── Settings surface (issue #93) ────────────────────────────────────

    [Fact]
    public async Task Anonymous_SettingsExternalUrl_Returns401()
    {
        var response = await CreateClient().GetAsync("/api/settings/external-url");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task AuthenticatedNonAdmin_SettingsExternalUrl_Returns403()
    {
        var response = await CreateClient("alice").GetAsync("/api/settings/external-url");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task UpdateExternalUrl_AdminWithoutCsrf_Returns403()
    {
        var response = await CreateClient(TestAuthHandler.AdminUser).PutAsync(
            "/api/settings/external-url",
            JsonContent(new { url = "https://certus.example.com:5001" }));

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task RenewHttpsCertificate_AdminWithoutCsrf_Returns403()
    {
        var response = await CreateClient(TestAuthHandler.AdminUser).PostAsync(
            "/api/settings/https-certificate/renew",
            JsonContent(new { }));

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    // ── Certificate revocation surface (issue #159) ─────────────────────
    // The highest blast radius write on the dashboard, so its guards get
    // their own explicit rows in this matrix even though they are the same
    // class level policy and middleware as everything above.

    [Fact]
    public async Task RevokeCertificate_Anonymous_Returns401()
    {
        var response = await CreateClient(csrf: true).PostAsync(
            "/api/certificates/1/revoke",
            JsonContent(new { reason = 1, serialNumber = "AA" }));

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task RevokeCertificate_AuthenticatedNonAdmin_Returns403()
    {
        var response = await CreateClient("alice", csrf: true).PostAsync(
            "/api/certificates/1/revoke",
            JsonContent(new { reason = 1, serialNumber = "AA" }));

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task RevokeCertificate_AdminWithoutCsrf_Returns403()
    {
        var response = await CreateClient(TestAuthHandler.AdminUser).PostAsync(
            "/api/certificates/1/revoke",
            JsonContent(new { reason = 1, serialNumber = "AA" }));

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    // ── Alert test send (issue #161) ────────────────────────────────────
    // It fires outbound SMTP and an HTTP POST on demand, so its guards get
    // explicit rows here. The CSRF row matters most: the client for this
    // endpoint uses plain fetch to read the 409 and 429 bodies, which does not
    // merge the CSRF header the way fetchJson does. Getting that wrong fails in
    // production only, because the CSRF middleware is not registered when
    // authentication is disabled, which is how every other test host runs.

    [Fact]
    public async Task SendTestAlert_Anonymous_Returns401()
    {
        var response = await CreateClient(csrf: true).PostAsync("/api/alerts/test", null);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task SendTestAlert_AuthenticatedNonAdmin_Returns403()
    {
        var response = await CreateClient("alice", csrf: true).PostAsync("/api/alerts/test", null);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task SendTestAlert_AdminWithoutCsrf_Returns403()
    {
        var response = await CreateClient(TestAuthHandler.AdminUser).PostAsync("/api/alerts/test", null);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    // ── SPA fallback must not mask API responses ────────────────────────

    [Fact]
    public async Task UnknownApiRoute_Anonymous_Returns401NotSpaHtml()
    {
        var response = await CreateClient().GetAsync("/api/nonexistent");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        response.Content.Headers.ContentType?.MediaType.Should().NotBe("text/html");
    }

    [Fact]
    public async Task UnknownApiRoute_Admin_Returns404NotSpaHtml()
    {
        var response = await CreateClient(TestAuthHandler.AdminUser).GetAsync("/api/nonexistent");

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
        response.Content.Headers.ContentType?.MediaType.Should().NotBe("text/html");
    }

    [Fact]
    public async Task UnknownAcmeRoute_Anonymous_Returns404NotSpaHtml()
    {
        var response = await CreateClient().GetAsync("/acme/WebServer/nonexistent");

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
        response.Content.Headers.ContentType?.MediaType.Should().NotBe("text/html");
    }

    [Fact]
    public async Task KnownApiRouteWrongMethod_Admin_Returns405()
    {
        // The /api fallback is an unconstrained catch-all, so it used to
        // absorb a method mismatch as a 404 the same way the ACME one did
        // (issue #147). /api/acme/eab/enforcement is GET and PUT only.
        var response = await CreateClient(TestAuthHandler.AdminUser, csrf: true)
            .DeleteAsync("/api/acme/eab/enforcement");

        response.StatusCode.Should().Be(HttpStatusCode.MethodNotAllowed);
        response.Content.Headers.Allow.Should().Contain(["GET", "PUT"]);
        response.Content.Headers.ContentType?.MediaType.Should().Be("application/problem+json");
    }

    [Fact]
    public async Task KnownApiRouteWrongMethod_Anonymous_StillReturns401()
    {
        // The fallback deliberately carries no [AllowAnonymous], so the deny by
        // default policy still answers first and the 405 never leaks which
        // admin routes exist (issue #27).
        var response = await CreateClient().DeleteAsync("/api/acme/eab/enforcement");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }
}

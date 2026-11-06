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
public class AuthIntegrationTests :
    IClassFixture<AuthWebApplicationFactory>,
    IClassFixture<KerberosOnlyWebApplicationFactory>
{
    private readonly AuthWebApplicationFactory _factory;
    private readonly KerberosOnlyWebApplicationFactory _kerberosOnly;

    public AuthIntegrationTests(AuthWebApplicationFactory factory, KerberosOnlyWebApplicationFactory kerberosOnly)
    {
        _factory = factory;
        _kerberosOnly = kerberosOnly;
    }

    private HttpClient CreateClient(string? user = null, bool csrf = false, string? authType = null) =>
        CreateClient(_factory, user, csrf, authType);

    private static HttpClient CreateClient(
        AuthWebApplicationFactory factory, string? user, bool csrf, string? authType)
    {
        var client = factory.CreateClient();
        if (user != null)
            client.DefaultRequestHeaders.Add(TestAuthHandler.UserHeader, user);
        if (authType != null)
            client.DefaultRequestHeaders.Add(TestAuthHandler.AuthTypeHeader, authType);
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

    // ── The service rights check (issue #440) ────────────────────────────

    public static TheoryData<string, string> ServiceRightsRoutes => new()
    {
        { "POST", "/api/setup/service-rights" },
        { "GET", "/api/settings/service-rights" },
        { "POST", "/api/settings/service-rights/check" },
    };

    private static HttpRequestMessage ServiceRightsRequest(string method, string path) =>
        new(new HttpMethod(method), path)
        {
            Content = method == "POST"
                ? JsonContent(new { caConnectionString = @"mockca.example.com\Mock Certificate Authority" })
                : null,
        };

    [Theory]
    [MemberData(nameof(ServiceRightsRoutes))]
    public async Task ServiceRights_Anonymous_Returns401(string method, string path)
    {
        var response = await CreateClient(csrf: true).SendAsync(ServiceRightsRequest(method, path));

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Theory]
    [MemberData(nameof(ServiceRightsRoutes))]
    public async Task ServiceRights_AuthenticatedNonAdmin_Returns403(string method, string path)
    {
        // The report maps the CA's permissions and the service's groups, which
        // is administrator information like the rest of the setup surface.
        var response = await CreateClient("alice", csrf: true).SendAsync(ServiceRightsRequest(method, path));

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Theory]
    [MemberData(nameof(ServiceRightsRoutes))]
    public async Task ServiceRights_AdminWithTheCsrfHeader_Returns200(string method, string path)
    {
        var response = await CreateClient(TestAuthHandler.AdminUser, csrf: true).SendAsync(ServiceRightsRequest(method, path));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Theory]
    [InlineData("/api/setup/service-rights")]
    [InlineData("/api/settings/service-rights/check")]
    public async Task ServiceRights_AdminWithoutTheCsrfHeader_Returns403(string path)
    {
        var response = await CreateClient(TestAuthHandler.AdminUser).SendAsync(ServiceRightsRequest("POST", path));

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
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

    // ── Kerberos only (issue #633, CRA risk R06) ────────────────────────
    // The package a Windows identity reports is what the middleware reads;
    // the test scheme names it through X-Test-Auth-Type.

    [Fact]
    public async Task NtlmAdmin_WithRequireKerberosOff_Returns200()
    {
        // The default for this release: NTLM is accepted, and only logged.
        var response = await CreateClient(TestAuthHandler.AdminUser, authType: "NTLM")
            .GetAsync("/api/certificates");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task NtlmAdmin_WithRequireKerberos_Returns401WithAProblemDocumentAndNoChallenge()
    {
        var response = await CreateClient(_kerberosOnly, TestAuthHandler.AdminUser, csrf: false, authType: "NTLM")
            .GetAsync("/api/certificates");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        response.Content.Headers.ContentType?.MediaType.Should().Be("application/problem+json");
        response.Headers.WwwAuthenticate.Should().BeEmpty(
            "a challenge would only make the browser repeat the same NTLM exchange");

        var body = await ParseJsonAsync(response);
        body.GetProperty("title").GetString().Should().Be(KerberosOnlyMiddleware.RefusalTitle);
        body.GetProperty("detail").GetString().Should().Contain("Auth:RequireKerberos");
        body.GetProperty("package").GetString().Should().Be("NTLM");
    }

    [Fact]
    public async Task KerberosAdmin_WithRequireKerberos_Returns200()
    {
        var response = await CreateClient(_kerberosOnly, TestAuthHandler.AdminUser, csrf: false, authType: "Kerberos")
            .GetAsync("/api/certificates");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task NtlmNonAdmin_WithRequireKerberos_Returns401NotForbidden()
    {
        // Refused before the policy runs, so an NTLM caller never learns
        // whether the account would have been an administrator.
        var response = await CreateClient(_kerberosOnly, "alice", csrf: false, authType: "NTLM")
            .GetAsync("/api/certificates");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        response.Content.Headers.ContentType?.MediaType.Should().Be("application/problem+json");
    }

    [Fact]
    public async Task Anonymous_WithRequireKerberos_StillGets401FromThePolicy()
    {
        // No identity, nothing for the middleware to judge: the deny by
        // default policy answers as before.
        var response = await CreateClient(_kerberosOnly, user: null, csrf: false, authType: null)
            .GetAsync("/api/certificates");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        response.Content.Headers.ContentType?.MediaType.Should().NotBe("application/problem+json");
    }

    [Fact]
    public async Task NtlmRefusal_IsCountedAsARefusedSignIn()
    {
        // The counter from #634 reads a 401 with credentials offered and no
        // challenge as a refusal, which is what the middleware answers; the
        // header stands in for the browser's Negotiate token, which the test
        // scheme ignores.
        var ntlm = CreateClient(_kerberosOnly, TestAuthHandler.AdminUser, csrf: false, authType: "NTLM");
        ntlm.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", "Negotiate dGVzdA==");
        var refused = await ntlm.GetAsync("/api/certificates");
        refused.StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        var response = await CreateClient(_kerberosOnly, TestAuthHandler.AdminUser, csrf: false, authType: "Kerberos")
            .GetAsync("/api/audit/sign-in-failures?days=1");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ParseJsonAsync(response);
        body.GetProperty("total").GetInt32().Should().BeGreaterThanOrEqualTo(1);
        body.GetProperty("sources").EnumerateArray()
            .Should().Contain(s => s.GetProperty("unauthorized").GetInt32() >= 1,
                "the refusal is a 401 after credentials were offered");
    }

    [Fact]
    public async Task NtlmIdentity_WithRequireKerberos_StillLoadsTheAnonymousShellAndHealth()
    {
        // Kestrel keeps NTLM credentials for the connection, so after one
        // refused API call the shell and its assets arrive authenticated too;
        // they must keep answering, or the browser cannot show the reason.
        var response = await CreateClient(_kerberosOnly, TestAuthHandler.AdminUser, csrf: false, authType: "NTLM")
            .GetAsync("/health");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task AcmeDirectory_WithRequireKerberos_StaysAnonymous()
    {
        var response = await CreateClient(_kerberosOnly, user: null, csrf: false, authType: null)
            .GetAsync("/acme/WebServer/directory");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
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

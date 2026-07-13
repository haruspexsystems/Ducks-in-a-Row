using System.Net;
using System.Text;
using System.Text.Json;
using Certus.Core.Acme.Models;
using Certus.Core.Setup;
using Microsoft.AspNetCore.Hosting;

namespace Certus.Web.Tests;

/// <summary>
/// Verifies that the wizard's template selection is enforced at the ACME
/// surface (issue #85). The factory seeds a wizard status file that enables
/// only the mock CA's WebServer template; the other CA published templates
/// must answer 403 unauthorized, and unknown templates keep the 404. The
/// shared factory (no status file) covers the allow all path in the existing
/// ACME tests.
/// </summary>
[Trait("Category", "Integration")]
public class EnabledTemplatesIntegrationTests
    : IClassFixture<EnabledTemplatesIntegrationTests.EnabledTemplatesFactory>
{
    private readonly HttpClient _client;

    public EnabledTemplatesIntegrationTests(EnabledTemplatesFactory factory)
    {
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task Directory_EnabledTemplate_Returns200()
    {
        var response = await _client.GetAsync("/acme/WebServer/directory");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Directory_DisabledTemplate_Returns403Unauthorized()
    {
        // Machine is published by the mock CA but was not enabled in the wizard.
        var response = await _client.GetAsync("/acme/Machine/directory");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        response.Content.Headers.ContentType?.MediaType.Should().Be("application/problem+json");

        var error = JsonSerializer.Deserialize<AcmeError>(
            await response.Content.ReadAsStringAsync());
        error!.Type.Should().Be(AcmeErrorType.Unauthorized);
        error.Status.Should().Be(403);
        error.Detail.Should().Contain("not enabled");
    }

    [Fact]
    public async Task Directory_DisabledTemplateByDisplayName_Returns403()
    {
        // The disabled response must not be dodged by addressing the same
        // template through its display name ("Computer" for Machine).
        var response = await _client.GetAsync("/acme/Computer/directory");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Directory_UnknownTemplate_Returns404()
    {
        var response = await _client.GetAsync("/acme/NonExistent/directory");

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);

        var error = JsonSerializer.Deserialize<AcmeError>(
            await response.Content.ReadAsStringAsync());
        error!.Type.Should().Be(AcmeErrorType.Malformed);
    }

    [Fact]
    public async Task NewOrder_DisabledTemplate_Returns403()
    {
        // The template gate runs before JWS authentication, so a placeholder
        // body still exercises it.
        var response = await PostJoseAsync("/acme/Machine/new-order");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);

        var error = JsonSerializer.Deserialize<AcmeError>(
            await response.Content.ReadAsStringAsync());
        error!.Type.Should().Be(AcmeErrorType.Unauthorized);
    }

    [Fact]
    public async Task NewAccount_DisabledTemplate_Returns403()
    {
        var response = await PostJoseAsync("/acme/Machine/new-account");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);

        var error = JsonSerializer.Deserialize<AcmeError>(
            await response.Content.ReadAsStringAsync());
        error!.Type.Should().Be(AcmeErrorType.Unauthorized);
    }

    private async Task<HttpResponseMessage> PostJoseAsync(string path)
    {
        var content = new StringContent("{}", Encoding.UTF8, "application/jose+json");
        return await _client.PostAsync(path, content);
    }

    /// <summary>
    /// Test factory that seeds a wizard status file enabling only the mock
    /// CA's WebServer template into the per factory data directory.
    /// </summary>
    public sealed class EnabledTemplatesFactory : CertusWebApplicationFactory
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);

            // Written before the host starts; the policy reads it lazily on
            // the first template resolution. The path mirrors
            // SetupStatus.GetStatusPath for the redirected DatabasePath.
            var status = new SetupStatus
            {
                SetupCompleted = true,
                EnabledTemplates = ["WebServer"],
            };
            status.Save(Path.Combine(TempDataDir, SetupStatus.FileName));
        }
    }
}

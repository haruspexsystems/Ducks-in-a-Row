using System.Net;
using System.Text;
using System.Text.Json;
using Certus.Core.Adcs;
using Certus.Core.Configuration;
using Certus.Core.Setup;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using NSubstitute;

namespace Certus.Web.Tests;

/// <summary>
/// Setup completion records the CA's own name for each template, not whichever of
/// its two forms the browser sent (issue #271). Every consumer that submits to the
/// CA already resolved again (PR #270); this is what makes the dashboard and the
/// settings page show one form.
///
/// Why a factory of its own: the shared one runs the mock CA, which has no published
/// list to resolve against and passes the set through. Clearing UseMockCa moves the
/// CA mode to "unconfigured", the honest state of a wizard that has not completed
/// yet, which takes the candidate CA from the request body. The client factory and
/// the URL probe are substitutes, so no COM and no network is touched. The
/// connection string stays empty in configuration, because StartupValidator refuses
/// a configured CA with auth disabled (SEC-F1).
/// </summary>
[Trait("Category", "Integration")]
public class CompletionTemplateResolutionIntegrationTests : IDisposable
{
    private const string Ca = "ca.contoso.com\\Contoso-CA";
    private const string ExternalUrl = "https://certus.contoso.com:5001";

    private sealed class Factory : CertusWebApplicationFactory
    {
        public IAdcsClient Client { get; } = Substitute.For<IAdcsClient>();

        public IExternalUrlProbe Probe { get; } = Substitute.For<IExternalUrlProbe>();

        public string DataDir => TempDataDir;

        public Factory()
        {
            Client.GetTemplatesAsync(Arg.Any<CancellationToken>()).Returns(
                new List<TemplateInfo>
                {
                    new("WebServer", "Web Server", "1.3.6.1.4.1.311.21.8.1"),
                    new("Machine", "Computer", "1.3.6.1.4.1.311.21.8.2"),
                });
            ProbeAnswers(reachable: true);
        }

        public void ProbeAnswers(bool reachable) =>
            Probe.ProbeAsync(Arg.Any<Uri>(), Arg.Any<string?>(), Arg.Any<CancellationToken>())
                .Returns(call => new ExternalUrlProbeResult(
                    Attempted: true,
                    Reachable: reachable,
                    DialedAuthority: $"{call.Arg<Uri>().Host}:{call.Arg<Uri>().Port}",
                    FailureKind: reachable ? null : "dns",
                    HttpStatusCode: reachable ? 200 : null));

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);

            builder.ConfigureServices(services =>
            {
                // PostConfigure, because UseMockCa is present in appsettings.json.
                services.PostConfigure<CertusOptions>(o => o.UseMockCa = false);

                var clientFactory = Substitute.For<IAdcsClientFactory>();
                clientFactory.Create(Arg.Any<string>()).Returns(_ => Client);
                services.AddSingleton(clientFactory);
                services.AddSingleton(Probe);
            });
        }
    }

    private readonly Factory _factory = new();
    private readonly HttpClient _client;

    public CompletionTemplateResolutionIntegrationTests()
    {
        _client = _factory.CreateClient();
    }

    public void Dispose()
    {
        _client.Dispose();
        _factory.Dispose();
    }

    private string StatusPath => Path.Combine(_factory.DataDir, SetupStatus.FileName);

    private Task<HttpResponseMessage> CompleteAsync(params string[] templates) =>
        _client.PostAsync("/api/setup/complete", new StringContent(
            JsonSerializer.Serialize(new
            {
                caConnectionString = Ca,
                enabledTemplates = templates,
                externalUrl = ExternalUrl,
            }),
            Encoding.UTF8,
            "application/json"));

    private static async Task<string?> ErrorOf(HttpResponseMessage response)
    {
        var body = JsonSerializer.Deserialize<JsonElement>(await response.Content.ReadAsStringAsync());
        return body.TryGetProperty("error", out var error) ? error.GetString() : null;
    }

    [Fact]
    public async Task A_display_name_is_recorded_as_the_programmatic_name()
    {
        var response = await CompleteAsync("Web Server");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        SetupStatus.Load(StatusPath).EnabledTemplates.Should().Equal("WebServer");
    }

    [Fact]
    public async Task A_name_in_another_case_is_recorded_in_the_cas_case()
    {
        (await CompleteAsync("webserver")).StatusCode.Should().Be(HttpStatusCode.OK);

        SetupStatus.Load(StatusPath).EnabledTemplates.Should().Equal("WebServer");
    }

    [Fact]
    public async Task Both_forms_of_one_template_are_recorded_once_in_first_seen_order()
    {
        (await CompleteAsync("Computer", "Web Server", "WebServer", "Machine"))
            .StatusCode.Should().Be(HttpStatusCode.OK);

        SetupStatus.Load(StatusPath).EnabledTemplates.Should().Equal("Machine", "WebServer");
    }

    [Fact]
    public async Task An_unpublished_template_is_refused_without_echoing_it_and_nothing_is_recorded()
    {
        var before = File.ReadAllText(StatusPath);

        var response = await CompleteAsync("WebServer", "NotOnThisCa");

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var error = await ErrorOf(response);
        error.Should().Contain("not published by the CA");
        error.Should().NotContain("NotOnThisCa");
        File.ReadAllText(StatusPath).Should().Be(before);
    }

    [Fact]
    public async Task Resolution_is_answered_before_the_url_probe()
    {
        // An unreachable URL alone would answer 422 and ask for a confirmation; a
        // template the CA does not publish is the earlier and the firmer answer.
        _factory.ProbeAnswers(reachable: false);

        var response = await CompleteAsync("NotOnThisCa");

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        await _factory.Probe.DidNotReceiveWithAnyArgs().ProbeAsync(default!, default, default);
    }

    [Fact]
    public async Task The_probe_aims_at_the_resolved_name()
    {
        (await CompleteAsync("Web Server")).StatusCode.Should().Be(HttpStatusCode.OK);

        await _factory.Probe.Received(1).ProbeAsync(
            Arg.Any<Uri>(), "WebServer", Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task A_ca_outage_answers_503_with_a_reason_the_wizard_can_show()
    {
        _factory.Client.GetTemplatesAsync(Arg.Any<CancellationToken>())
            .Returns<IReadOnlyList<TemplateInfo>>(_ => throw new CaUnavailableException("RPC server unavailable"));

        var response = await CompleteAsync("WebServer");

        response.StatusCode.Should().Be(HttpStatusCode.ServiceUnavailable);
        // A string, not { error: true }: the wizard shows body.error as the reason.
        (await ErrorOf(response)).Should().Be("The certificate authority is unavailable. Try again shortly.");
    }

    [Fact]
    public async Task A_ca_that_refuses_the_service_account_answers_503_with_its_remedy()
    {
        _factory.Client.GetTemplatesAsync(Arg.Any<CancellationToken>())
            .Returns<IReadOnlyList<TemplateInfo>>(_ => throw new CaAccessDeniedException(
                CaAccessDeniedException.EnrollPermissionMessage, new UnauthorizedAccessException()));

        var response = await CompleteAsync("WebServer");

        response.StatusCode.Should().Be(HttpStatusCode.ServiceUnavailable);
        (await ErrorOf(response)).Should().Be(CaAccessDeniedException.EnrollPermissionMessage);
    }
}

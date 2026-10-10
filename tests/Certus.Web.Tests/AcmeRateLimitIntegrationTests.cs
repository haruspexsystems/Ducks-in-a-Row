using System.Net;
using System.Text;
using System.Text.Json;
using Certus.Core.Acme.Models;
using Certus.Core.Security;
using FluentAssertions;
using Microsoft.AspNetCore.Hosting;

namespace Certus.Web.Tests;

/// <summary>
/// A throttled ACME client used to get a bare 429 with no body, because the
/// limiter was configured with a rejection status and nothing else (issue
/// #147). RFC 8555 §6.6 has an error code for exactly this condition and asks
/// for a Retry-After header, so the rejection now carries both. The dashboard
/// is deliberately left alone: only the protocol surface gets a body.
///
/// Issue #263 added the rest of what a refusal has to say. Four policies shared
/// one "Too many requests" string, so neither the client nor the operator could
/// tell which limit had been reached and therefore which setting to change.
/// Every policy is exercised here, one factory per test, because each policy owns
/// its own partition and a shared factory would leak a spent budget between tests.
/// </summary>
[Trait("Category", "Integration")]
public class AcmeRateLimitIntegrationTests
{
    private const string Template = "WebServer";

    private static StringContent Jose() =>
        new("{}", Encoding.UTF8, "application/jose+json");

    /// <summary>
    /// Sends the given request twice against a host whose named policy permits
    /// exactly one, and returns the refused second response.
    /// </summary>
    private static async Task<HttpResponseMessage> RefuseSecondAsync(
        string limitKey,
        Func<HttpClient, Task<HttpResponseMessage>> send,
        params (string Key, string Value)[] extraSettings)
    {
        var settings = new List<(string, string)> { ($"Certus:RateLimiting:{limitKey}", "1") };
        settings.AddRange(extraSettings);

        using var factory = new ThrottledFactory([.. settings]);
        var client = factory.CreateClient();

        // The first request is expected to fail on its body; only the second matters.
        (await send(client)).Dispose();
        return await send(client);
    }

    private static async Task<AcmeError> ReadProblemAsync(HttpResponseMessage response)
    {
        response.Content.Headers.ContentType?.MediaType.Should().Be("application/problem+json");

        var error = JsonSerializer.Deserialize<AcmeError>(
            await response.Content.ReadAsStringAsync());

        error.Should().NotBeNull();
        return error!;
    }

    [Fact]
    public async Task RateLimitedAcmeRequest_Returns429ProblemDocument()
    {
        var response = await RefuseSecondAsync(
            "NewAccountLimit", c => c.PostAsync($"/acme/{Template}/new-account", Jose()));

        response.StatusCode.Should().Be(HttpStatusCode.TooManyRequests);

        var error = await ReadProblemAsync(response);
        error.Type.Should().Be(AcmeErrorType.RateLimited);
        error.Status.Should().Be(429);
        error.Detail.Should().NotBeNullOrEmpty();

        response.Headers.RetryAfter.Should().NotBeNull(
            "RFC 8555 §6.6 asks the server to tell the client when to retry");
        response.Headers.Contains("Replay-Nonce").Should().BeTrue(
            "an ACME protocol response carries a nonce even when it is an error");
    }

    [Fact]
    public async Task RefusedRequest_ReportsOneSegmentAsRetryAfter_NotTheWholeWindow()
    {
        // The default window is 60 seconds over 6 segments. A fixed window limiter
        // reports the whole 60 through its own lease metadata; a sliding one reports
        // no metadata at all and this falls back to the segment. Asserting 10 is
        // what fails if the limiter is ever put back to a fixed window.
        var response = await RefuseSecondAsync(
            "NewOrderLimit", c => c.PostAsync($"/acme/{Template}/new-order", Jose()));

        response.StatusCode.Should().Be(HttpStatusCode.TooManyRequests);
        response.Headers.RetryAfter!.Delta.Should().Be(TimeSpan.FromSeconds(10));
    }

    [Theory]
    [InlineData("NewAccountLimit", "new-account", "new account requests")]
    [InlineData("NewOrderLimit", "new-order", "new order requests")]
    public async Task RefusedRequest_NamesThePolicyThatRefusedIt(
        string limitKey, string route, string expectedPhrase)
    {
        var response = await RefuseSecondAsync(
            limitKey, c => c.PostAsync($"/acme/{Template}/{route}", Jose()));

        var error = await ReadProblemAsync(response);
        error.Detail.Should().Contain(expectedPhrase);

        // The QA extended cycle buckets a failure by matching the client's output
        // against 429|rate limit|rateLimited|too many, so every wording has to keep
        // one of those or a load run silently reclassifies its refusals.
        error.Detail.Should().ContainEquivalentOf("too many");
    }

    [Fact]
    public async Task GeneralPolicy_RefusesWithoutNamingAMoreSpecificLimit()
    {
        var response = await RefuseSecondAsync(
            "GeneralLimit", c => c.GetAsync($"/acme/{Template}/directory"));

        response.StatusCode.Should().Be(HttpStatusCode.TooManyRequests);

        var error = await ReadProblemAsync(response);
        error.Detail.Should().Contain("Too many requests.");
    }

    [Fact]
    public async Task OrderPolling_IsRateLimitedUnderThePollPolicy()
    {
        // This endpoint carried no policy at all before issue #263, so it could not
        // be refused however hard it was hit. Narrowing PollLimit alone proves both
        // that it is limited now and that it is on the poll budget rather than the
        // general one, which this factory leaves at its default.
        var response = await RefuseSecondAsync(
            "PollLimit", c => c.PostAsync($"/acme/{Template}/order/any-order-id", Jose()));

        response.StatusCode.Should().Be(HttpStatusCode.TooManyRequests);

        var error = await ReadProblemAsync(response);
        error.Detail.Should().Contain("authorization and order polling requests");
    }

    [Fact]
    public async Task AuthorizationPolling_IsOnThePollBudgetNotTheGeneralOne()
    {
        var response = await RefuseSecondAsync(
            "PollLimit", c => c.PostAsync($"/acme/{Template}/authz/any-authz-id", Jose()));

        response.StatusCode.Should().Be(HttpStatusCode.TooManyRequests);

        var error = await ReadProblemAsync(response);
        error.Detail.Should().Contain("authorization and order polling requests");
    }

    [Fact]
    public async Task PollingBudget_IsSeparateFromTheGeneralBudget()
    {
        // A general budget of one, already spent, must not refuse a poll. That
        // separation is the point of the split: polling costs as much as validation
        // takes, and it used to spend the same budget as everything else.
        using var factory = new ThrottledFactory(("Certus:RateLimiting:GeneralLimit", "1"));
        var client = factory.CreateClient();

        (await client.GetAsync($"/acme/{Template}/directory")).Dispose();

        var refusedGeneral = await client.GetAsync($"/acme/{Template}/directory");
        refusedGeneral.StatusCode.Should().Be(HttpStatusCode.TooManyRequests);

        var poll = await client.PostAsync($"/acme/{Template}/order/any-order-id", Jose());
        poll.StatusCode.Should().NotBe(HttpStatusCode.TooManyRequests);
    }

    [Fact]
    public async Task RefusedRequest_CarriesNoHelpLinkUnlessOneIsConfigured()
    {
        var response = await RefuseSecondAsync(
            "NewAccountLimit", c => c.PostAsync($"/acme/{Template}/new-account", Jose()));

        response.Headers.Contains("Link").Should().BeFalse(
            "the product ships no outbound pointer of its own");
    }

    [Fact]
    public async Task RefusedRequest_CarriesAHelpLinkNamingThePolicyWhenConfigured()
    {
        var response = await RefuseSecondAsync(
            "NewAccountLimit",
            c => c.PostAsync($"/acme/{Template}/new-account", Jose()),
            ("Certus:RateLimiting:HelpUrl", "https://runbook.example.test/acme-limits"));

        response.Headers.GetValues("Link").Should().ContainSingle()
            .Which.Should().Be(
                "<https://runbook.example.test/acme-limits#" +
                AcmeRateLimitPolicies.NewAccount + ">; rel=\"help\"");
    }

    /// <summary>
    /// The shared factory turns rate limiting off so the rest of the suite can
    /// hammer the endpoints; this one turns it back on and narrows whichever
    /// limits a test names. Each instance is its own host, so each test starts
    /// with an unspent budget.
    /// </summary>
    private sealed class ThrottledFactory : CertusWebApplicationFactory
    {
        private readonly (string Key, string Value)[] _settings;

        public ThrottledFactory(params (string Key, string Value)[] settings)
        {
            _settings = settings;
        }

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);

            builder.UseSetting("Certus:RateLimiting:Enabled", "true");
            builder.UseSetting("Certus:RateLimiting:WindowSeconds", "60");

            foreach (var (key, value) in _settings)
                builder.UseSetting(key, value);
        }
    }
}

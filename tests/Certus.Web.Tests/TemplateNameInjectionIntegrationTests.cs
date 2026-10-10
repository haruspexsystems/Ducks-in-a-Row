using System.Net;
using System.Text;
using System.Text.Json;
using Certus.Core.Setup;

namespace Certus.Web.Tests;

/// <summary>
/// The setup wizard must not accept a certificate template name that could
/// smuggle an extra ADCS request attribute (issue #175, the CVE-2026-54121
/// "CertiGhost" class). Completion records the enabled set and the webserver
/// certificate renewal later submits an entry from it, so the refusal has to
/// happen before the name reaches the status file. Uses its own factory
/// instance per test because completion locks setup.
/// </summary>
[Trait("Category", "Integration")]
public class TemplateNameInjectionIntegrationTests : IDisposable
{
    private sealed class Factory : CertusWebApplicationFactory
    {
        public string DataDir => TempDataDir;
    }

    private readonly Factory _factory = new();
    private readonly HttpClient _client;

    public TemplateNameInjectionIntegrationTests()
    {
        _client = _factory.CreateClient();
    }

    public void Dispose()
    {
        _client.Dispose();
        _factory.Dispose();
        GC.SuppressFinalize(this);
    }

    private string StatusPath => Path.Combine(_factory.DataDir, SetupStatus.FileName);

    private static StringContent JsonContent(object payload) => new(
        JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

    private static async Task<JsonElement> ParseJsonAsync(HttpResponseMessage response)
    {
        var json = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<JsonElement>(json);
    }

    [Fact]
    public async Task Complete_TemplateCarryingTheCertiGhostPayload_Returns400AndRecordsNothing()
    {
        var response = await _client.PostAsync("/api/setup/complete", JsonContent(new
        {
            enabledTemplates = new[]
            {
                "WebServer\ncdc:evil.attacker.example\nrmd:DC01.contoso.com",
            },
            externalUrl = "https://certus.contoso.com:5001",
        }));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var error = (await ParseJsonAsync(response)).GetProperty("error").GetString();
        error.Should().Contain("control character");
        // The refusal must not echo the payload back out of the API.
        error.Should().NotContain("cdc:");

        SetupStatus.Load(StatusPath).SetupCompleted.Should().BeFalse();
    }

    [Fact]
    public async Task Complete_SecondTemplateCarryingAControlCharacter_Returns400()
    {
        // Every entry is checked, not only the first: renewal reads the first,
        // but the ACME template policy matches against all of them.
        var response = await _client.PostAsync("/api/setup/complete", JsonContent(new
        {
            enabledTemplates = new[] { "WebServer", "Machine\rcdc:evil.attacker.example" },
            externalUrl = "https://certus.contoso.com:5001",
        }));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        SetupStatus.Load(StatusPath).SetupCompleted.Should().BeFalse();
    }

    [Fact]
    public async Task Draft_TemplateCarryingAControlCharacter_Returns400()
    {
        // A draft writes the same EnabledTemplates field completion does, and
        // the template policy does not consult SetupCompleted (issue #101), so
        // a draft set is live for ACME matching and is logged when the policy
        // loads it. The draft endpoint has to refuse what completion refuses.
        var response = await _client.PostAsync("/api/setup/draft", JsonContent(new
        {
            caConnectionString = "ca.contoso.com\\Contoso-CA",
            enabledTemplates = new[] { "WebServer\ncdc:evil.attacker.example" },
            externalUrl = "https://certus.contoso.com:5001",
            wizardStep = "url",
        }));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        SetupStatus.Load(StatusPath).EnabledTemplates
            .Should().NotContain(t => t.Contains("cdc:"));
    }

    [Fact]
    public async Task Draft_OrdinaryTemplateNames_StillSave()
    {
        var response = await _client.PostAsync("/api/setup/draft", JsonContent(new
        {
            caConnectionString = "ca.contoso.com\\Contoso-CA",
            enabledTemplates = new[] { "WebServer" },
            externalUrl = "https://certus.contoso.com:5001",
            wizardStep = "url",
        }));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        SetupStatus.Load(StatusPath).EnabledTemplates.Should().Equal("WebServer");
    }

    [Fact]
    public async Task Complete_TemplateCarryingABidiOverride_Returns400()
    {
        // A right to left override cannot smuggle an attribute, but it makes the
        // recorded name display as a different name wherever it is echoed.
        var response = await _client.PostAsync("/api/setup/complete", JsonContent(new
        {
            enabledTemplates = new[] { "WebServer" + (char)0x202E + "reverseMe" },
            externalUrl = "https://certus.contoso.com:5001",
        }));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var error = (await ParseJsonAsync(response)).GetProperty("error").GetString();
        error.Should().Contain("formatting character");

        SetupStatus.Load(StatusPath).SetupCompleted.Should().BeFalse();
    }

    /// <summary>
    /// The ACME surface takes its template from a URL path segment, so a client
    /// can percent encode a control character into it and have ASP.NET decode it
    /// back before any Certus code runs.
    ///
    /// Two separate refusals stand behind this. The route segment only ever
    /// selects: OrderController creates the order with the CA's own published
    /// name from TemplateService.ResolveAsync, so a smuggled name matches
    /// nothing published and never reaches ADCS. And UrlCharacterGuardMiddleware
    /// refuses the request outright, before the request logger can render the
    /// decoded path into the log file. This asserts the second, because it is
    /// the one that keeps the rejected value out of the log and out of the
    /// response body. Without it the unknown template problem document echoes
    /// the name straight back, and Serilog writes it to the log file.
    ///
    /// The directory endpoint is the cheapest place to drive it: it is an
    /// unauthenticated GET, no JWS and no account.
    /// </summary>
    [Theory]
    [InlineData("%0A", "line feed, the ADCS attribute pair separator")]
    [InlineData("%0D", "carriage return")]
    [InlineData("%0D%0A", "carriage return line feed")]
    [InlineData("%09", "tab")]
    [InlineData("%7F", "delete")]
    [InlineData("%C2%85", "the C1 next line, U+0085")]
    [InlineData("%E2%80%AE", "a right to left override, U+202E")]
    [InlineData("%E2%80%8B", "a zero width space, U+200B")]
    [InlineData("%C2%AD", "a soft hyphen, U+00AD")]
    // The issue #234 payload, reproduced over HTTP. Categories Zl and Zp are
    // neither Control nor Format, so this exact request was answered normally
    // until the guards moved onto the shared scanner.
    [InlineData("%E2%80%A8", "the Unicode line separator, U+2028")]
    [InlineData("%E2%80%A9", "the Unicode paragraph separator, U+2029")]
    public async Task AcmeDirectory_TemplateSegmentCarryingAnUnsafeCharacter_IsRefused(
        string encoded, string because)
    {
        var response = await _client.GetAsync(
            $"/acme/WebServer{encoded}cdc:evil.attacker.example{encoded}rmd:DC01.contoso.com/directory");

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest,
            $"a URL carrying {because} is refused before it is logged");

        // An ACME path answers the ACME envelope, so a client renders a real
        // error rather than "unexpected response" (issue #147's reasoning,
        // applied to this guard by issue #235). The detail names the code point
        // and nothing else.
        response.Content.Headers.ContentType!.MediaType
            .Should().Be("application/problem+json");
        (await ParseJsonAsync(response)).GetProperty("type").GetString()
            .Should().Be("urn:ietf:params:acme:error:malformed");

        var body = await response.Content.ReadAsStringAsync();
        body.Should().Contain("U+");
        body.Should().NotContain("cdc:");
        body.Should().NotContain("rmd:");
    }

    [Fact]
    public async Task AcmeDirectory_DisplayNameCarryingASoftHyphen_SaysToUseTheProgrammaticName()
    {
        // Issue #235's own shape. A template display name is free text out of
        // Active Directory, a soft hyphen is what a paste from a word processor
        // leaves in one, and issue #17 lets a client address the template by
        // that name. The operator sees a correct looking name everywhere, so
        // the refusal has to say what to do instead.
        var response = await _client.GetAsync("/acme/Web%C2%ADServer/directory");

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var body = await response.Content.ReadAsStringAsync();
        body.Should().Contain("U+00AD");
        body.Should().Contain("formatting character");
        body.Should().Contain("programmatic name");
    }

    [Fact]
    public async Task Api_PathCarryingASoftHyphen_KeepsThePlainErrorBody()
    {
        // The dashboard side is deliberately unchanged: only /acme gets the
        // protocol envelope.
        var response = await _client.GetAsync("/api/setup/%C2%ADstatus");

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        response.Content.Headers.ContentType!.MediaType
            .Should().NotBe("application/problem+json");
        (await response.Content.ReadAsStringAsync())
            .Should().Contain("The request URL contains a control, line separator, or formatting character.");
    }

    [Fact]
    public async Task AcmeDirectory_CleanButUnpublishedTemplate_IsTheOrdinaryRefusal()
    {
        // The guard is about characters, not about which templates exist. A
        // clean name the CA does not publish still gets the ordinary ACME
        // unknown template answer, so the new refusal has not swallowed the old
        // one.
        var response = await _client.GetAsync("/acme/NoSuchTemplate/directory");

        // Both refusals carry the "malformed" code, which is the registry's
        // general purpose one and what AcmeProblemResults uses for every fault
        // RFC 8555 gives no code of its own. The status code is what tells the
        // two apart, so it is asserted here rather than left implicit.
        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
        (await ParseJsonAsync(response)).GetProperty("type").GetString()
            .Should().Be("urn:ietf:params:acme:error:malformed");
    }

    [Fact]
    public async Task AcmeDirectory_EncodedControlCharacterInTheQueryString_IsHarmless()
    {
        // The counterpart to the path theory above, and the reason the guard
        // does not extend to the query string: ASP.NET decodes the path but
        // leaves QueryString.Value raw, so "%0A" here stays three characters
        // and reaches no log as a newline. Asserted so a later reader does not
        // widen the guard to cover an exposure that is not there.
        var response = await _client.GetAsync("/acme/WebServer/directory?x=%0Aforged");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task AcmeDirectory_OrdinaryTemplate_StillAnswers()
    {
        // The negative control for the theory above: the enabled template the
        // shared factory seeds still resolves and still returns a directory.
        var response = await _client.GetAsync("/acme/WebServer/directory");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await ParseJsonAsync(response)).GetProperty("newOrder").GetString()
            .Should().EndWith("/acme/WebServer/new-order");
    }

    [Fact]
    public async Task Complete_OrdinaryTemplateNames_StillComplete()
    {
        // The guard must not narrow what a legitimate install can record: a
        // display name with spaces and a version suffix is normal.
        var response = await _client.PostAsync("/api/setup/complete", JsonContent(new
        {
            enabledTemplates = new[] { "WebServer", "Contoso Web Server v2.1" },
            externalUrl = "https://certus.contoso.com:5001",
        }));

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var status = SetupStatus.Load(StatusPath);
        status.SetupCompleted.Should().BeTrue();
        status.EnabledTemplates.Should().Equal("WebServer", "Contoso Web Server v2.1");
    }
}

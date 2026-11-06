using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Certus.Web.Authentication;
using Certus.Web.Controllers.Settings;

namespace Certus.Service.Tests.Modules;

/// <summary>
/// The licence API through the real service host pipeline (licence design section 13.2, issue
/// #413): the fallback and AdminOnly policies, the CSRF header guard, the 415 that
/// <c>[Consumes("application/jose+json")]</c> answers and the 413 that the size cap answers. The
/// controller's unit tests pin the attributes; these prove the pipeline acts on them.
///
/// <para>TestServer does not enforce <c>[RequestSizeLimit]</c>, which is a Kestrel feature, so the 413
/// here is the action's own read cap, the half of the size rule that holds under any server. The
/// Kestrel half is the attribute, which LicenceControllerTests pins; nothing here proves Kestrel
/// acts on it, and the action's cap is why that does not matter.</para>
/// </summary>
public class LicenceApiPipelineTests
{
    private const string Route = "/api/settings/licence";

    private static readonly byte[] Licence = "header.PIPELINE-TEST-LICENCE.signature"u8.ToArray();
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    [Fact]
    public async Task AnAnonymousCaller_IsChallenged()
    {
        using var factory = new AuthServiceHostFactory();
        using var http = factory.CreateClient();

        var response = await http.GetAsync(Route);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task AUserWhoIsNotAnAdministrator_IsRefusedEveryRoute()
    {
        using var factory = new AuthServiceHostFactory();
        using var http = factory.CreateClient();

        foreach (var request in EveryRoute(withCsrf: true))
        {
            request.Headers.Add(TestAuthHandler.UserHeader, "someone");
            var response = await http.SendAsync(request);
            response.StatusCode.Should().Be(HttpStatusCode.Forbidden, $"{request.Method} {request.RequestUri}");
        }

        (await StatusAsAdminAsync(http)).Stored.Active.Should().BeFalse();
    }

    [Fact]
    public async Task AnAdministrator_CanReadTheStatus()
    {
        using var factory = new AuthServiceHostFactory();
        using var http = factory.CreateClient();

        var status = await StatusAsAdminAsync(http);

        status.Module.State.Should().Be("NotPresent");
        status.Licence.Status.Should().Be("None");
    }

    [Fact]
    public async Task EveryChange_WithoutTheCsrfHeader_IsRefused()
    {
        using var factory = new AuthServiceHostFactory();
        using var http = factory.CreateClient();

        foreach (var request in EveryRoute(withCsrf: false).Where(r => r.Method != HttpMethod.Get))
        {
            request.Headers.Add(TestAuthHandler.UserHeader, TestAuthHandler.AdminUser);
            var response = await http.SendAsync(request);
            response.StatusCode.Should().Be(HttpStatusCode.Forbidden, $"{request.Method} {request.RequestUri}");
            (await response.Content.ReadAsStringAsync()).Should().Contain(CertusPolicies.CsrfHeaderName);
        }

        (await StatusAsAdminAsync(http)).Stored.Active.Should().BeFalse();
    }

    [Theory]
    [InlineData("application/json")]
    [InlineData("text/plain")]
    [InlineData("application/octet-stream")]
    public async Task AnUploadThatIsNotAJws_Is415(string contentType)
    {
        using var factory = new AuthServiceHostFactory();
        using var http = factory.CreateClient();

        foreach (var path in new[] { Route, Route + "/inspect" })
        {
            var request = AsAdmin(path == Route ? HttpMethod.Put : HttpMethod.Post, path, Licence, contentType);
            var response = await http.SendAsync(request);
            response.StatusCode.Should().Be(HttpStatusCode.UnsupportedMediaType, path);
        }

        (await StatusAsAdminAsync(http)).Stored.Active.Should().BeFalse();
    }

    [Fact]
    public async Task AnUploadOverTheCap_Is413()
    {
        using var factory = new AuthServiceHostFactory();
        using var http = factory.CreateClient();
        var oversized = new byte[LicenceController.MaxLicenceBytes + 1];

        foreach (var path in new[] { Route, Route + "/inspect" })
        {
            var request = AsAdmin(path == Route ? HttpMethod.Put : HttpMethod.Post, path, oversized);
            var response = await http.SendAsync(request);
            response.StatusCode.Should().Be(HttpStatusCode.RequestEntityTooLarge, path);
        }

        (await StatusAsAdminAsync(http)).Stored.Active.Should().BeFalse();
    }

    [Fact]
    public async Task AnAdministrator_WithTheHeaderAndAJws_InstallsAndRemoves()
    {
        using var factory = new AuthServiceHostFactory();
        using var http = factory.CreateClient();

        var put = await http.SendAsync(AsAdmin(HttpMethod.Put, Route, Licence));
        put.StatusCode.Should().Be(HttpStatusCode.OK, await put.Content.ReadAsStringAsync());
        (await put.Content.ReadFromJsonAsync<LicenceStatusResponse>(Json))!.Licence.Status.Should().Be("StoredNotVerified");

        var delete = await http.SendAsync(AsAdmin(HttpMethod.Delete, Route, body: null));
        delete.StatusCode.Should().Be(HttpStatusCode.OK);

        var status = await StatusAsAdminAsync(http);
        status.Stored.Should().Be(new Certus.Core.Modules.LicenceStoreView(false, true));
    }

    /// <summary>One request for each of the six routes, with a valid JWS body where one is taken.</summary>
    private static IEnumerable<HttpRequestMessage> EveryRoute(bool withCsrf)
    {
        yield return Request(HttpMethod.Get, Route, null, withCsrf);
        yield return Request(HttpMethod.Post, Route + "/inspect", Licence, withCsrf);
        yield return Request(HttpMethod.Put, Route, Licence, withCsrf);
        yield return Request(HttpMethod.Delete, Route, null, withCsrf);
        yield return Request(HttpMethod.Post, Route + "/restore-previous", null, withCsrf);
        yield return Request(HttpMethod.Post, Route + "/retry-module", null, withCsrf);
    }

    private static HttpRequestMessage AsAdmin(HttpMethod method, string path, byte[]? body, string contentType = LicenceController.LicenceMediaType)
    {
        var request = Request(method, path, body, withCsrf: true, contentType);
        request.Headers.Add(TestAuthHandler.UserHeader, TestAuthHandler.AdminUser);
        return request;
    }

    private static HttpRequestMessage Request(
        HttpMethod method, string path, byte[]? body, bool withCsrf, string contentType = LicenceController.LicenceMediaType)
    {
        var request = new HttpRequestMessage(method, path);
        if (body is not null)
        {
            request.Content = new ByteArrayContent(body);
            request.Content.Headers.ContentType = new MediaTypeHeaderValue(contentType);
        }

        if (withCsrf)
            request.Headers.Add(CertusPolicies.CsrfHeaderName, "1");
        return request;
    }

    private static async Task<LicenceStatusResponse> StatusAsAdminAsync(HttpClient http)
    {
        var response = await http.SendAsync(AsAdmin(HttpMethod.Get, Route, body: null));
        response.StatusCode.Should().Be(HttpStatusCode.OK, await response.Content.ReadAsStringAsync());
        return (await response.Content.ReadFromJsonAsync<LicenceStatusResponse>(Json))!;
    }
}

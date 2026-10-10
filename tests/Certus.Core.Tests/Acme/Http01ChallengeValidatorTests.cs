using System.Net;
using Certus.Core.Acme.Services;
using Microsoft.Extensions.Logging.Abstractions;

namespace Certus.Core.Tests.Acme;

/// <summary>
/// Tests for Http01ChallengeValidator. http-01 is the default challenge type, created for
/// every non wildcard authorization, and its branches were previously uncovered: a wrong
/// body and a non success status are genuine failures (do not retry), a blocked address is
/// a permanent server side request forgery rejection, and a connection error or timeout is
/// transient (the worker may retry). RFC 8555 §8.3.
/// </summary>
public class Http01ChallengeValidatorTests
{
    private const string TestToken = "tok-123";
    private const string TestThumbprint = "thumb-abc";
    private const string TestDomain = "example.com";
    private static readonly string ExpectedKeyAuth = $"{TestToken}.{TestThumbprint}";

    private static Http01ChallengeValidator CreateValidator(
        Func<HttpRequestMessage, HttpResponseMessage> handler) =>
        new(new HttpClient(new MockHttpHandler(handler)),
            NullLogger<Http01ChallengeValidator>.Instance);

    private static ChallengeValidationContext Context(
        string domain = TestDomain, string token = TestToken, string thumbprint = TestThumbprint) =>
        new("dns", domain, token, thumbprint, "test-template");

    [Fact]
    public void ChallengeType_IsHttp01()
    {
        var sut = CreateValidator(_ => new HttpResponseMessage(HttpStatusCode.OK));

        sut.ChallengeType.Should().Be("http-01");
    }

    [Fact]
    public async Task Validate_CorrectKeyAuth_Succeeds()
    {
        string? requestedUrl = null;
        var sut = CreateValidator(request =>
        {
            requestedUrl = request.RequestUri?.ToString();
            // A trailing newline also exercises the validator's Trim().
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent($"{ExpectedKeyAuth}\n")
            };
        });

        var result = await sut.ValidateAsync(Context());

        result.IsValid.Should().BeTrue();
        requestedUrl.Should().Be($"http://{TestDomain}/.well-known/acme-challenge/{TestToken}");
    }

    [Fact]
    public async Task Validate_WrongBody_FailsNotTransient()
    {
        var sut = CreateValidator(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("not-the-key-authorization")
        });

        var result = await sut.ValidateAsync(Context());

        result.IsValid.Should().BeFalse();
        result.Transient.Should().BeFalse(); // a wrong answer is genuine, not retryable
        result.ErrorDetail.Should().Contain("key authorization");
    }

    [Fact]
    public async Task Validate_Non2xxStatus_FailsNotTransient()
    {
        var sut = CreateValidator(_ => new HttpResponseMessage(HttpStatusCode.NotFound));

        var result = await sut.ValidateAsync(Context());

        result.IsValid.Should().BeFalse();
        result.Transient.Should().BeFalse(); // the server answered; 404 is a genuine failure
        result.ErrorDetail.Should().Contain("404");
    }

    [Fact]
    public async Task Validate_BlockedAddress_FailsPermanently()
    {
        // The egress guard rejected the resolved address (SSRF). This must be a permanent
        // rejection, not a transient blip the worker keeps retrying.
        var sut = CreateValidator(_ => throw new HttpRequestException(
            "blocked", new AddressBlockedException("blocked.example.com")));

        var result = await sut.ValidateAsync(Context());

        result.IsValid.Should().BeFalse();
        result.Transient.Should().BeFalse();
        result.ErrorDetail.Should().Contain("not permitted");
    }

    [Fact]
    public async Task Validate_SteeredToABlockedPort_SaysSoRatherThanBlamingTheAddress()
    {
        // Only a redirect can reach this, since the validator builds its own
        // URL on port 80. The address resolved perfectly well, so reporting it
        // as a blocked address would send the client to check DNS and firewall
        // rules for a problem that is neither.
        var sut = CreateValidator(_ => throw new HttpRequestException(
            "blocked", new AddressBlockedException("redirect.example.com", 8080)));

        var result = await sut.ValidateAsync(Context());

        result.IsValid.Should().BeFalse();
        result.Transient.Should().BeFalse();
        result.ErrorDetail.Should().Contain("port 8080");
        result.ErrorDetail.Should().NotContain("resolves to an address");
    }

    [Fact]
    public async Task Validate_ConnectionError_IsTransient()
    {
        var sut = CreateValidator(_ => throw new HttpRequestException("connection refused"));

        var result = await sut.ValidateAsync(Context());

        result.IsValid.Should().BeFalse();
        result.Transient.Should().BeTrue(); // no response received — a transport failure
        result.ErrorDetail.Should().NotBeNullOrEmpty();
    }

    [Theory]
    // An identifier that carried its own port. Before issue #345 this was a
    // legal identifier and the fetch URL was built by interpolation, so the
    // client chose which internal port the validator opened a connection to
    // and the answer told it whether anything was listening there.
    [InlineData("10.0.0.5:22")]
    // A fragment marker truncates the well known path, so the request that
    // actually goes out asks for "/" at the host.
    [InlineData("example.com#")]
    // A path fragment moves the request off the challenge path entirely.
    [InlineData("example.com/../../admin")]
    // Userinfo changes who the request presents as.
    [InlineData("user@internal.host")]
    public async Task Validate_IdentifierThatIsNotAWholeAuthority_NeverLeavesTheProcess(
        string domain)
    {
        // The second fence. The new-order grammar refuses all of these long
        // before a challenge exists, so this can only fire if that grammar is
        // ever loosened; the point is that loosening it cannot silently reopen
        // the authority.
        var requested = 0;
        var sut = CreateValidator(_ =>
        {
            requested++;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(ExpectedKeyAuth)
            };
        });

        var result = await sut.ValidateAsync(Context(domain));

        result.IsValid.Should().BeFalse();
        result.Transient.Should().BeFalse();
        result.ErrorDetail.Should().Contain("challenge URL");
        requested.Should().Be(0, "no request may go out for an identifier that is not a host");
    }

    [Fact]
    public async Task Validate_GoodIdentifier_RequestsPort80AndNothingElse()
    {
        Uri? requested = null;
        var sut = CreateValidator(request =>
        {
            requested = request.RequestUri;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(ExpectedKeyAuth)
            };
        });

        var result = await sut.ValidateAsync(Context());

        result.IsValid.Should().BeTrue();
        requested!.Scheme.Should().Be("http");
        requested.Host.Should().Be(TestDomain);
        requested.Port.Should().Be(80);
        requested.IsDefaultPort.Should().BeTrue();
        requested.UserInfo.Should().BeEmpty();
        requested.Query.Should().BeEmpty();
        requested.Fragment.Should().BeEmpty();
        requested.AbsolutePath.Should().Be($"/.well-known/acme-challenge/{TestToken}");
    }

    [Fact]
    public async Task Validate_Timeout_IsTransient()
    {
        // A timeout surfaces as TaskCanceledException while the caller's token is not cancelled.
        var sut = CreateValidator(_ => throw new TaskCanceledException());

        var result = await sut.ValidateAsync(Context());

        result.IsValid.Should().BeFalse();
        result.Transient.Should().BeTrue();
    }

    #region Helpers

    /// <summary>
    /// Mock handler that runs a function per request. A synchronous throw from the function is
    /// surfaced as a faulted task, matching how HttpClient observes a handler failure.
    /// </summary>
    private sealed class MockHttpHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _handler;

        public MockHttpHandler(Func<HttpRequestMessage, HttpResponseMessage> handler)
        {
            _handler = handler;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            try { return Task.FromResult(_handler(request)); }
            catch (Exception ex) { return Task.FromException<HttpResponseMessage>(ex); }
        }
    }

    #endregion
}

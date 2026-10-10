using Certus.Core.Acme.Services;
using Microsoft.Extensions.Options;

namespace Certus.Core.Tests.Acme;

/// <summary>
/// The connect callback's port rule (issue #345). The egress guard reads the
/// host of a validation target and nothing else, so until this rule existed an
/// identifier that carried its own port sent the validator at an arbitrary
/// internal service on an arbitrary port, and whether the connection succeeded
/// was readable from the challenge result. The address is now only half of what
/// gets vetted.
/// </summary>
public class ChallengeHttpHandlerFactoryTests
{
    [Theory]
    // The port RFC 8555 section 8.3 makes the http-01 request on.
    [InlineData(80, true)]
    // The same section permits a redirect to https, which AllowRedirects turns
    // on, so 443 has to stay reachable or that option would be broken by this.
    [InlineData(443, true)]
    [InlineData(22, false)]
    [InlineData(8080, false)]
    [InlineData(3389, false)]
    [InlineData(445, false)]
    [InlineData(1, false)]
    [InlineData(65535, false)]
    public void IsPermittedPort_AllowsOnlyTheTwoChallengePorts(int port, bool expected)
    {
        ChallengeHttpHandlerFactory.IsPermittedPort(port).Should().Be(expected);
    }

    [Fact]
    public async Task Connect_ToAPortThatIsNotAChallengePort_IsRefusedBeforeAnyLookup()
    {
        // The refusal sits above the resolve, so this test opens no socket and
        // asks no resolver anything: the host below is an RFC 2606 reserved
        // name and is never looked up.
        using var client = new HttpClient(
            ChallengeHttpHandlerFactory.Create(Guard(), new ChallengeValidationOptions()));

        var connect = async () =>
            await client.GetAsync("http://validation-target.invalid:8080/x");

        var thrown = (await connect.Should().ThrowAsync<HttpRequestException>()).Which;

        thrown.InnerException.Should().BeOfType<AddressBlockedException>()
            .Which.Message.Should().Contain("port 8080");
    }

    private static AddressGuard Guard() =>
        new(Options.Create(new ChallengeValidationOptions()));
}

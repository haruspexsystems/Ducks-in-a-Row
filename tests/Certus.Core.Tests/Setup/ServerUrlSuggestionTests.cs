using Certus.Core.Setup;

namespace Certus.Core.Tests.Setup;

/// <summary>
/// The suggested external URL seeds the wizard's Server URL field: the
/// machine's DNS name plus the port the service actually listens on, with
/// the port always written out explicitly (the issue #89 trap).
/// </summary>
public class ServerUrlSuggestionTests
{
    [Fact]
    public void Build_UsesTheHttpsEndpointPort()
    {
        var url = ServerUrlSuggestion.Build(
            "https://0.0.0.0:5001", "http://0.0.0.0:5000", null, "CERTUS", "home.local");

        url.Should().Be("https://certus.home.local:5001");
    }

    [Fact]
    public void Build_ParsesTheKestrelWildcardHosts()
    {
        ServerUrlSuggestion.Build("https://*:8443", null, null, "CERTUS", "home.local")
            .Should().Be("https://certus.home.local:8443");
        ServerUrlSuggestion.Build("https://+:8443", null, null, "CERTUS", "home.local")
            .Should().Be("https://certus.home.local:8443");
    }

    [Fact]
    public void Build_FallsBackToTheUrlsValue()
    {
        // Development hosts configure listening through "urls"
        // (ASPNETCORE_URLS / launchSettings) rather than Kestrel endpoints.
        var url = ServerUrlSuggestion.Build(
            null, null, "http://localhost:5000;https://localhost:5001", "CERTUS", "home.local");

        url.Should().Be("https://certus.home.local:5001");
    }

    [Fact]
    public void Build_FallsBackToHttpWhenNoHttpsEndpointExists()
    {
        var url = ServerUrlSuggestion.Build(
            null, "http://0.0.0.0:5000", null, "CERTUS", "home.local");

        url.Should().Be("http://certus.home.local:5000");
    }

    [Fact]
    public void Build_DefaultsToTheShippedHttpsPortWhenNothingParses()
    {
        var url = ServerUrlSuggestion.Build(null, null, null, "CERTUS", "home.local");

        url.Should().Be("https://certus.home.local:5001");
    }

    [Fact]
    public void Build_KeepsThePortExplicitEvenFor443()
    {
        // A portless URL sends ACME clients to the scheme default; keeping
        // the port explicit means the suggestion never depends on that.
        var url = ServerUrlSuggestion.Build(
            "https://0.0.0.0:443", null, null, "CERTUS", "home.local");

        url.Should().Be("https://certus.home.local:443");
    }

    [Fact]
    public void BuildFqdn_JoinsHostAndDomainLowercase()
    {
        ServerUrlSuggestion.BuildFqdn("CERTUS", "Home.Local").Should().Be("certus.home.local");
    }

    [Fact]
    public void BuildFqdn_WorkgroupHostHasNoDomain()
    {
        ServerUrlSuggestion.BuildFqdn("CERTUS", "").Should().Be("certus");
    }

    [Fact]
    public void BuildFqdn_AlreadyQualifiedHostIsNotDoubled()
    {
        ServerUrlSuggestion.BuildFqdn("certus.home.local", "home.local")
            .Should().Be("certus.home.local");
    }

    [Theory]
    [InlineData(null, false)]
    [InlineData("", false)]
    [InlineData("not a url", false)]
    [InlineData("http://0.0.0.0:5000", false)] // wrong scheme for the https probe
    [InlineData("https://0.0.0.0:5001", true)]
    public void TryParseAuthority_AcceptsOnlyTheRequestedScheme(string? endpoint, bool expected)
    {
        ServerUrlSuggestion.TryParseAuthority(endpoint, "https", out _).Should().Be(expected);
    }
}

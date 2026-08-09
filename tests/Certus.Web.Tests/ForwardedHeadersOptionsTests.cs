using System.Net;
using Certus.Core.Configuration;
using Certus.Web.Authentication;
using Microsoft.AspNetCore.HttpOverrides;

namespace Certus.Web.Tests;

/// <summary>
/// Unit tests for the trusted proxy allowlist behind forwarded header handling
/// (issue #27, SEC-F1 follow-up). The allowlist decides whether the X-Forwarded-For,
/// X-Forwarded-Host, and X-Forwarded-Proto headers are honored: For corrects
/// HttpContext.Connection.RemoteIpAddress (what the ACME rate limiter keys on); Host and
/// Proto correct request.Host and request.Scheme (what AcmeUrl builds ACME URLs from). An
/// empty or all invalid list must leave forwarded headers ignored so a client cannot spoof
/// any of them.
/// </summary>
public class ForwardedHeadersOptionsTests
{
    [Fact]
    public void Build_NoTrustedProxies_ReturnsNull()
    {
        var options = new AuthOptions { TrustedProxies = [] };

        var result = CertusAuthExtensions.BuildForwardedHeadersOptions(options);

        result.Should().BeNull();
    }

    [Fact]
    public void Build_ValidProxies_HonorsForwardedForHostAndProtoAndListsThem()
    {
        var options = new AuthOptions { TrustedProxies = ["10.0.0.5", "::1"] };

        var result = CertusAuthExtensions.BuildForwardedHeadersOptions(options);

        result.Should().NotBeNull();
        result!.ForwardedHeaders.Should().Be(
            ForwardedHeaders.XForwardedFor
            | ForwardedHeaders.XForwardedHost
            | ForwardedHeaders.XForwardedProto);
        result.KnownIPNetworks.Should().BeEmpty();
        result.KnownProxies.Should().HaveCount(2);
        result.KnownProxies.Should().Contain(IPAddress.Parse("10.0.0.5"));
        result.KnownProxies.Should().Contain(IPAddress.Parse("::1"));
    }

    [Fact]
    public void Build_MixedValidAndInvalid_KeepsOnlyParseableAddresses()
    {
        var options = new AuthOptions { TrustedProxies = ["192.168.1.10", "not-an-ip", ""] };

        var result = CertusAuthExtensions.BuildForwardedHeadersOptions(options);

        result.Should().NotBeNull();
        result!.KnownProxies.Should().HaveCount(1);
        result.KnownProxies.Should().Contain(IPAddress.Parse("192.168.1.10"));
    }

    [Fact]
    public void Build_AllInvalid_ReturnsNull()
    {
        var options = new AuthOptions { TrustedProxies = ["not-an-ip", "999.999.999.999"] };

        var result = CertusAuthExtensions.BuildForwardedHeadersOptions(options);

        result.Should().BeNull();
    }
}

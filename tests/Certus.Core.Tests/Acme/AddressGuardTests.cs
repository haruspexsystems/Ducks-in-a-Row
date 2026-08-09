using System.Net;
using Certus.Core.Acme.Services;
using Microsoft.Extensions.Options;

namespace Certus.Core.Tests.Acme;

public class AddressGuardTests
{
    private static AddressGuard Guard(ChallengeValidationOptions? options = null) =>
        new(Options.Create(options ?? new ChallengeValidationOptions()));

    [Theory]
    [InlineData("127.0.0.1")]            // loopback
    [InlineData("127.5.6.7")]            // anywhere in 127.0.0.0/8
    [InlineData("::1")]                  // IPv6 loopback
    [InlineData("169.254.169.254")]      // cloud metadata endpoint
    [InlineData("169.254.0.1")]          // IPv4 link local
    [InlineData("fe80::1")]              // IPv6 link local
    [InlineData("fc00::1")]              // IPv6 unique local
    public void IsBlocked_DefaultsDeny_LoopbackLinkLocalUniqueLocal(string ip)
    {
        Guard().IsBlocked(IPAddress.Parse(ip)).Should().BeTrue();
    }

    [Theory]
    [InlineData("8.8.8.8")]              // public
    [InlineData("192.168.1.10")]         // RFC 1918 - allowed by default (internal CA)
    [InlineData("10.0.0.5")]             // RFC 1918 - allowed by default
    [InlineData("172.16.0.1")]           // RFC 1918 - allowed by default
    [InlineData("2606:4700:4700::1111")] // public IPv6
    public void IsBlocked_DefaultsAllow_PublicAndPrivate(string ip)
    {
        Guard().IsBlocked(IPAddress.Parse(ip)).Should().BeFalse();
    }

    [Fact]
    public void IsBlocked_HonoursAdditionalBlockedCidrs()
    {
        var guard = Guard(new ChallengeValidationOptions
        {
            AdditionalBlockedCidrs = ["10.0.0.0/8"]
        });

        guard.IsBlocked(IPAddress.Parse("10.1.2.3")).Should().BeTrue();
        guard.IsBlocked(IPAddress.Parse("11.0.0.1")).Should().BeFalse();
    }

    [Theory]
    [InlineData("10.0.0.0")]             // bottom of 10.0.0.0/8
    [InlineData("10.0.0.5")]
    [InlineData("10.255.255.255")]       // top of 10.0.0.0/8
    [InlineData("172.16.0.0")]           // bottom of 172.16.0.0/12
    [InlineData("172.24.10.20")]         // middle of 172.16.0.0/12
    [InlineData("172.31.255.255")]       // top of 172.16.0.0/12
    [InlineData("192.168.0.0")]          // bottom of 192.168.0.0/16
    [InlineData("192.168.1.10")]
    [InlineData("192.168.255.255")]      // top of 192.168.0.0/16
    [InlineData("::ffff:10.0.0.5")]      // IPv4 mapped IPv6 normalises before the check
    public void IsBlocked_BlockPrivateRanges_BlocksEachRfc1918Range(string ip)
    {
        var guard = Guard(new ChallengeValidationOptions { BlockPrivateRanges = true });
        guard.IsBlocked(IPAddress.Parse(ip)).Should().BeTrue();
    }

    [Theory]
    [InlineData("9.255.255.255")]        // one below 10.0.0.0/8
    [InlineData("11.0.0.0")]             // one above 10.0.0.0/8
    [InlineData("172.15.255.255")]       // one below 172.16.0.0/12
    [InlineData("172.32.0.0")]           // one above 172.16.0.0/12
    [InlineData("192.167.255.255")]      // one below 192.168.0.0/16
    [InlineData("192.169.0.0")]          // one above 192.168.0.0/16
    [InlineData("100.64.0.1")]           // CGNAT is not RFC 1918; use AdditionalBlockedCidrs
    [InlineData("8.8.8.8")]              // public IPv4
    [InlineData("2606:4700:4700::1111")] // public IPv6
    public void IsBlocked_BlockPrivateRanges_LeavesNeighbouringAndPublicAlone(string ip)
    {
        var guard = Guard(new ChallengeValidationOptions { BlockPrivateRanges = true });
        guard.IsBlocked(IPAddress.Parse(ip)).Should().BeFalse();
    }

    [Fact]
    public void IsBlocked_BlockPrivateRanges_ComposesWithAdditionalBlockedCidrs()
    {
        var guard = Guard(new ChallengeValidationOptions
        {
            BlockPrivateRanges = true,
            AdditionalBlockedCidrs = ["100.64.0.0/10"]
        });

        guard.IsBlocked(IPAddress.Parse("10.1.2.3")).Should().BeTrue();    // the flag
        guard.IsBlocked(IPAddress.Parse("100.64.0.1")).Should().BeTrue();  // the operator CIDR
        guard.IsBlocked(IPAddress.Parse("8.8.8.8")).Should().BeFalse();    // neither
    }

    [Fact]
    public void IsBlockedLiteral_ScreensLocalhostAndIpLiterals()
    {
        var guard = Guard();
        guard.IsBlockedLiteral("localhost").Should().BeTrue();
        guard.IsBlockedLiteral("LOCALHOST").Should().BeTrue();
        guard.IsBlockedLiteral("127.0.0.1").Should().BeTrue();
        guard.IsBlockedLiteral("example.com").Should().BeFalse();
    }

    [Fact]
    public void IsBlockedLiteral_BlockPrivateRanges_ScreensPrivateIpLiterals()
    {
        Guard(new ChallengeValidationOptions { BlockPrivateRanges = true })
            .IsBlockedLiteral("192.168.1.10").Should().BeTrue();
        Guard().IsBlockedLiteral("192.168.1.10").Should().BeFalse();
    }

    [Fact]
    public async Task ResolveAndVet_BlockedLiteral_Throws()
    {
        var guard = Guard();
        await Assert.ThrowsAsync<AddressBlockedException>(
            () => guard.ResolveAndVetAsync("127.0.0.1", CancellationToken.None).AsTask());
        await Assert.ThrowsAsync<AddressBlockedException>(
            () => guard.ResolveAndVetAsync("localhost", CancellationToken.None).AsTask());
    }

    [Fact]
    public async Task ResolveAndVet_AllowedLiteral_ReturnsAddress()
    {
        var ip = await Guard().ResolveAndVetAsync("8.8.8.8", CancellationToken.None);
        ip.Should().Be(IPAddress.Parse("8.8.8.8"));
    }

    [Fact]
    public void Constructor_InvalidCidr_FailsFast()
    {
        var act = () => Guard(new ChallengeValidationOptions { AdditionalBlockedCidrs = ["not-a-cidr"] });
        act.Should().Throw<FormatException>();
    }
}

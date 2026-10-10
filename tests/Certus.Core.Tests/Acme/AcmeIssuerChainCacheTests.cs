using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certus.Core.Acme.Services;
using Certus.Core.Adcs;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Certus.Core.Tests.Acme;

/// <summary>
/// The cache behind the ACME issuer endpoint, the "up" link target RFC 8555
/// §7.4.2 requires. The reason it exists is that the route is unauthenticated
/// and every client follows the link after every issuance, so what matters here
/// is that a hit costs the CA nothing and that an outage is not remembered.
/// </summary>
public class AcmeIssuerChainCacheTests
{
    private readonly IAdcsClient _adcs = Substitute.For<IAdcsClient>();
    private readonly FakeTimeProvider _time = new();

    private AcmeIssuerChainCache NewCache() =>
        new(_adcs, NullLogger<AcmeIssuerChainCache>.Instance, _time);

    [Fact]
    public async Task GetPemChainAsync_RendersEveryCertificateInTheChain()
    {
        _adcs.GetCaCertificateChainAsync(Arg.Any<CancellationToken>())
            .Returns(new[] { SelfSignedDer("CN=Issuing CA"), SelfSignedDer("CN=Root CA") });

        var pem = await NewCache().GetPemChainAsync();

        pem.Should().NotBeNull();
        CountOccurrences(pem!, "-----BEGIN CERTIFICATE-----").Should().Be(2);
        CountOccurrences(pem!, "-----END CERTIFICATE-----").Should().Be(2);
    }

    [Fact]
    public async Task GetPemChainAsync_WithinTtl_DoesNotAskTheCaAgain()
    {
        _adcs.GetCaCertificateChainAsync(Arg.Any<CancellationToken>())
            .Returns(new[] { SelfSignedDer("CN=Issuing CA") });
        var cache = NewCache();

        var first = await cache.GetPemChainAsync();
        _time.Advance(AcmeIssuerChainCache.Ttl - TimeSpan.FromMinutes(1));
        var second = await cache.GetPemChainAsync();

        second.Should().Be(first);
        await _adcs.Received(1).GetCaCertificateChainAsync(Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task GetPemChainAsync_AfterTtl_AsksTheCaAgain()
    {
        _adcs.GetCaCertificateChainAsync(Arg.Any<CancellationToken>())
            .Returns(new[] { SelfSignedDer("CN=Issuing CA") });
        var cache = NewCache();

        await cache.GetPemChainAsync();
        _time.Advance(AcmeIssuerChainCache.Ttl + TimeSpan.FromMinutes(1));
        await cache.GetPemChainAsync();

        await _adcs.Received(2).GetCaCertificateChainAsync(Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task GetPemChainAsync_CaUnavailable_ReturnsNullAndDoesNotCacheTheFailure()
    {
        // An outage must not be remembered for a whole TTL, or one unlucky moment
        // takes the issuer endpoint down for an hour after the CA has recovered.
        var der = SelfSignedDer("CN=Issuing CA");
        _adcs.GetCaCertificateChainAsync(Arg.Any<CancellationToken>())
            .Returns(
                _ => throw new CaUnavailableException("down"),
                _ => Task.FromResult<IReadOnlyList<byte[]>>(new[] { der }));
        var cache = NewCache();

        var duringOutage = await cache.GetPemChainAsync();
        var afterRecovery = await cache.GetPemChainAsync();

        duringOutage.Should().BeNull();
        afterRecovery.Should().NotBeNull();
    }

    private static byte[] SelfSignedDer(string subject)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        return certificate.RawData;
    }

    private static int CountOccurrences(string haystack, string needle)
    {
        var count = 0;
        var index = 0;
        while ((index = haystack.IndexOf(needle, index, StringComparison.Ordinal)) != -1)
        {
            count++;
            index += needle.Length;
        }
        return count;
    }
}

using Certus.Core.Adcs;

namespace Certus.Core.Tests.Adcs;

/// <summary>
/// The unconfigured client must surface every CA operation as
/// CaUnavailableException so the web layer's existing 503 ca-unavailable
/// handling applies while no CA is connected.
/// </summary>
public class UnconfiguredAdcsClientTests
{
    private readonly UnconfiguredAdcsClient _client = new();

    [Fact]
    public async Task GetCaInfo_ThrowsCaUnavailable()
    {
        var act = () => _client.GetCaInfoAsync();

        await act.Should().ThrowAsync<CaUnavailableException>()
            .WithMessage("*setup wizard*");
    }

    [Fact]
    public async Task GetTemplates_ThrowsCaUnavailable()
    {
        var act = () => _client.GetTemplatesAsync();

        await act.Should().ThrowAsync<CaUnavailableException>();
    }

    [Fact]
    public async Task GetCaCertificateChain_ThrowsCaUnavailable()
    {
        var act = () => _client.GetCaCertificateChainAsync();

        await act.Should().ThrowAsync<CaUnavailableException>();
    }

    [Fact]
    public async Task SubmitCertificateRequest_ThrowsCaUnavailable()
    {
        var act = () => _client.SubmitCertificateRequestAsync("WebServer", [0x30]);

        await act.Should().ThrowAsync<CaUnavailableException>();
    }

    [Fact]
    public async Task GetCertificate_ThrowsCaUnavailable()
    {
        var act = () => _client.GetCertificateAsync(1);

        await act.Should().ThrowAsync<CaUnavailableException>();
    }

    [Fact]
    public async Task QueryCertificates_ThrowsCaUnavailable()
    {
        var act = () => _client.QueryCertificatesAsync(new CertificateQuery());

        await act.Should().ThrowAsync<CaUnavailableException>();
    }

    [Fact]
    public async Task RevokeCertificate_ThrowsCaUnavailable()
    {
        var act = () => _client.RevokeCertificateAsync("0A0B", 0);

        await act.Should().ThrowAsync<CaUnavailableException>();
    }
}

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Certus.Service.Tests;

/// <summary>
/// The fixed password PFX an earlier release kept is deleted on every boot,
/// including a boot that serves a configured certificate and never touches
/// the fallback (issue #635). This host is given a certificate path, so the
/// fallback branch is not taken, and the file still has to go.
/// </summary>
public class ServiceHostLegacyPfxTests : IClassFixture<ServiceHostLegacyPfxTests.ConfiguredCertificateFactory>
{
    private readonly ConfiguredCertificateFactory _factory;

    public ServiceHostLegacyPfxTests(ConfiguredCertificateFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public void ABootThatServesAConfiguredCertificate_StillDeletesTheLegacyPfx()
    {
        // Booting the host is the act under test; resolving a service forces it.
        _factory.Services.GetRequiredService<IOptions<Certus.Core.Configuration.CertusOptions>>();

        File.Exists(Path.Combine(_factory.DataDirectory, SelfSignedHttpsCertificate.LegacyFileName))
            .Should().BeFalse("the legacy file is a private key under a password every copy of the product knew");
        File.Exists(_factory.ConfiguredCertificatePath)
            .Should().BeTrue("the operator's own certificate file is not the host's to touch");
        File.Exists(Path.Combine(_factory.DataDirectory, SelfSignedHttpsCertificate.FileName))
            .Should().BeFalse("a host serving a configured certificate generates no fallback");
    }

    public sealed class ConfiguredCertificateFactory : ServiceHostFactory
    {
        public string ConfiguredCertificatePath => Path.Combine(DataDirectory, "operator.pfx");

        protected override void SeedDataDirectory(string dataDirectory)
        {
            // A PFX at the legacy name, as every release up to 1.0.0 wrote it.
            File.WriteAllBytes(
                Path.Combine(dataDirectory, SelfSignedHttpsCertificate.LegacyFileName), MintPfx("certus-dev"));
            // And the operator's configured certificate, which the host must leave alone.
            File.WriteAllBytes(ConfiguredCertificatePath, MintPfx("operator-password"));
        }

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            builder.UseSetting("Kestrel:Endpoints:Https:Certificate:Path", ConfiguredCertificatePath);
            builder.UseSetting("Kestrel:Endpoints:Https:Certificate:Password", "operator-password");
        }

        private static byte[] MintPfx(string password)
        {
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest("CN=legacy.example.com", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using var certificate = request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
            return certificate.Export(X509ContentType.Pfx, password);
        }
    }
}

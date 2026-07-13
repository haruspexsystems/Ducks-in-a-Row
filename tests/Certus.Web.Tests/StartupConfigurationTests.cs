using Certus.Web;

namespace Certus.Web.Tests;

/// <summary>
/// Guards for Certus.Web host startup. Certus.Web is used for development and
/// integration testing and never wires a real ADCS client (that is Certus.Service's
/// job). Setting Certus:CaConnectionString here used to be logged as configured while
/// leaving IAdcsClient unregistered, so the host crashed opaquely when
/// CertificateSyncService was constructed. WebHostGuards.EnsureNoRealCaConfigured now
/// fails fast at startup. Regression coverage for the core configuration review
/// (reviews/2026-06-19-core-configuration.md).
/// </summary>
public class StartupConfigurationTests
{
    [Fact]
    public void EnsureNoRealCaConfigured_WithCaConnectionString_Throws()
    {
        Action act = () => WebHostGuards.EnsureNoRealCaConfigured(@"CA01\Contoso Issuing CA");

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*does not host a real CA*");
    }

    [Fact]
    public void EnsureNoRealCaConfigured_WithoutCaConnectionString_DoesNotThrow()
    {
        Action act = () => WebHostGuards.EnsureNoRealCaConfigured(null);

        act.Should().NotThrow();
    }
}

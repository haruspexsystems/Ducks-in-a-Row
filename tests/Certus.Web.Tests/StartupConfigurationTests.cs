using Certus.Core.Configuration;
using Certus.Web;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Certus.Web.Tests;

/// <summary>
/// Guards for Certus.Web host startup. Certus.Web is used for development and
/// integration testing and never wires a real ADCS client (that is Certus.Service's
/// job). Setting Certus:CaConnectionString here used to be logged as configured while
/// leaving IAdcsClient unregistered, so the host crashed opaquely when
/// CertificateSyncService was constructed. WebHostGuards.EnsureNoRealCaConfigured now
/// fails fast at startup. Regression coverage for the core configuration review
/// (reviews/2026-06-19-core-configuration.md).
///
/// <para>
/// Issue #305 widened the guard to the settings overlay. Configuration is the source a
/// developer sets by hand; the overlay is the source the setup wizard writes, and it is
/// the one a real installation actually uses. Both are covered here.
/// </para>
/// </summary>
public class StartupConfigurationTests
{
    [Fact]
    public void EnsureNoRealCaConfigured_WithCaConnectionString_Throws()
    {
        using var overlay = new TempOverlay();
        var options = new CertusOptions
        {
            CaConnectionString = @"CA01\Contoso Issuing CA",
            SettingsOverlayPath = overlay.FilePath,
        };

        Action act = () => WebHostGuards.EnsureNoRealCaConfigured(options);

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*does not host a real CA*");
    }

    [Fact]
    public void EnsureNoRealCaConfigured_WithoutCaConnectionString_DoesNotThrow()
    {
        using var overlay = new TempOverlay();
        var options = new CertusOptions
        {
            CaConnectionString = null,
            SettingsOverlayPath = overlay.FilePath,
        };

        Action act = () => WebHostGuards.EnsureNoRealCaConfigured(options);

        act.Should().NotThrow();
    }

    /// <summary>
    /// The defect issue #305 turned up. The setup wizard writes the CA to the
    /// settings overlay, not to appsettings.json, and Certus.Web does not load
    /// the overlay as a configuration source. So a fully configured installation
    /// presents a null Certus:CaConnectionString to this host, and the guard has
    /// to read the overlay itself or it passes on exactly the machine where the
    /// dev host does the most damage.
    /// </summary>
    [Fact]
    public void EnsureNoRealCaConfigured_WithCaInTheOverlayOnly_Throws()
    {
        using var overlay = new TempOverlay();
        SettingsOverlay.Save(
            new SettingsOverlay.OverlaySettings(@"CA01\Contoso Issuing CA", null),
            overlay.FilePath);

        var options = new CertusOptions
        {
            CaConnectionString = null,
            SettingsOverlayPath = overlay.FilePath,
        };

        Action act = () => WebHostGuards.EnsureNoRealCaConfigured(options);

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*does not host one*");
    }

    [Fact]
    public void EnsureNoRealCaConfigured_WithAnOverlayThatHasNoCa_DoesNotThrow()
    {
        using var overlay = new TempOverlay();
        SettingsOverlay.Save(
            new SettingsOverlay.OverlaySettings(null, "https://certs.contoso.com"),
            overlay.FilePath);

        var options = new CertusOptions { SettingsOverlayPath = overlay.FilePath };

        Action act = () => WebHostGuards.EnsureNoRealCaConfigured(options);

        act.Should().NotThrow();
    }

    [Fact]
    public void EnsureNoRealCaConfigured_WithNoOverlayFile_DoesNotThrow()
    {
        using var overlay = new TempOverlay();

        var options = new CertusOptions { SettingsOverlayPath = overlay.FilePath };

        Action act = () => WebHostGuards.EnsureNoRealCaConfigured(options);

        act.Should().NotThrow();
    }

    /// <summary>
    /// A file that cannot be parsed is not evidence of a configured CA, so the
    /// guard warns and allows startup. Throwing here would turn a stray edit in
    /// the data directory into a dev host that refuses to run at all.
    /// </summary>
    [Fact]
    public void EnsureNoRealCaConfigured_WithAnUnreadableOverlay_DoesNotThrow()
    {
        using var overlay = new TempOverlay();
        File.WriteAllText(overlay.FilePath, "{ this is not json");

        var options = new CertusOptions { SettingsOverlayPath = overlay.FilePath };

        Action act = () => WebHostGuards.EnsureNoRealCaConfigured(options);

        act.Should().NotThrow();
    }

    /// <summary>
    /// Configuration still wins when both carry a value: it is checked first, so
    /// the message names the key the developer actually set.
    /// </summary>
    [Fact]
    public void EnsureNoRealCaConfigured_WithCaInConfiguration_ReportsTheConfigurationKey()
    {
        using var overlay = new TempOverlay();
        SettingsOverlay.Save(
            new SettingsOverlay.OverlaySettings(@"CA02\Overlay CA", null), overlay.FilePath);

        var options = new CertusOptions
        {
            CaConnectionString = @"CA01\Contoso Issuing CA",
            SettingsOverlayPath = overlay.FilePath,
        };

        Action act = () => WebHostGuards.EnsureNoRealCaConfigured(options);

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*Certus:CaConnectionString is set*");
    }

    /// <summary>
    /// The guard above runs on the options copy Program.cs binds from configuration
    /// itself, not on IOptions&lt;CertusOptions&gt;, so the factory's PostConfigure cannot
    /// reach it. CertusWebApplicationFactory therefore supplies the overlay path through
    /// UseSetting as well, and this asserts that it lands where the manual bind reads it.
    ///
    /// <para>
    /// Worth its own test because nothing else fails without it. A developer machine with
    /// no CA in its real ProgramData overlay passes the whole suite either way, so
    /// deleting the UseSetting line is silent here and breaks every web test on a machine
    /// that does have one.
    /// </para>
    /// </summary>
    [Trait("Category", "Integration")]
    public class OverlayRedirectionTests : IClassFixture<CertusWebApplicationFactory>
    {
        private readonly CertusWebApplicationFactory _factory;

        public OverlayRedirectionTests(CertusWebApplicationFactory factory) => _factory = factory;

        [Fact]
        public void TheHostConfigurationCarriesTheRedirectedOverlayPath()
        {
            var configuration = _factory.Services.GetRequiredService<IConfiguration>();

            var configured = configuration[
                $"{CertusOptions.SectionName}:{nameof(CertusOptions.SettingsOverlayPath)}"];

            configured.Should().NotBeNullOrWhiteSpace(
                "the manually bound options copy in Program.cs reads the overlay path from " +
                "configuration, so a DI only redirect would leave it on the real default");
            configured.Should().NotBe(CertusPaths.SettingsOverlayPath);

            // The binder is what the guard actually goes through, so assert on its result
            // rather than on the raw string alone.
            var bound = configuration.GetSection(CertusOptions.SectionName).Get<CertusOptions>()!;
            SettingsOverlay.ResolvePath(bound).Should().Be(configured);
        }
    }

    private sealed class TempOverlay : IDisposable
    {
        private readonly string _directory = Path.Combine(
            Path.GetTempPath(), "certus-overlay-tests-" + Guid.NewGuid().ToString("N"));

        public TempOverlay() => Directory.CreateDirectory(_directory);

        public string FilePath => Path.Combine(_directory, "settings.json");

        public void Dispose()
        {
            try
            {
                Directory.Delete(_directory, recursive: true);
            }
            catch (IOException)
            {
                // A leftover temp directory is not worth failing a test over.
            }
        }
    }
}

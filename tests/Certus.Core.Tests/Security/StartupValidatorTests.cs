using Certus.Core.Configuration;
using Certus.Core.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute;

namespace Certus.Core.Tests.Security;

public class StartupValidatorTests
{
    private readonly ILogger<StartupValidator> _logger;

    public StartupValidatorTests()
    {
        _logger = Substitute.For<ILogger<StartupValidator>>();
    }

    private StartupValidator CreateValidator(
        CertusOptions options,
        AuthOptions? authOptions = null,
        AcmeRateLimitOptions? rateLimitOptions = null,
        IConfiguration? configuration = null)
    {
        return new StartupValidator(
            Options.Create(options),
            Options.Create(authOptions ?? new AuthOptions()),
            Options.Create(rateLimitOptions ?? new AcmeRateLimitOptions()),
            configuration ?? new ConfigurationManager(),
            _logger);
    }

    /// <summary>A configuration that produces zero warnings on its own.</summary>
    private static CertusOptions FullyConfigured() => new()
    {
        CaConnectionString = "ca\\TestCA",
        ExternalUrl = "https://certus.example.com",
        DatabasePath = "C:\\ProgramData\\Certus\\certus.db",
        SyncIntervalMinutes = 15,
    };

    [Fact]
    public void Validate_FullyConfigured_ReturnsZeroWarnings()
    {
        var warnings = CreateValidator(FullyConfigured()).Validate();

        warnings.Should().Be(0);
    }

    [Fact]
    public void Validate_NoCaConnection_ReturnsWarning()
    {
        var options = new CertusOptions
        {
            CaConnectionString = null,
            ExternalUrl = "https://certus.example.com",
        };

        var warnings = CreateValidator(options).Validate();

        warnings.Should().BeGreaterThan(0);
    }

    [Fact]
    public void Validate_MockCaExplicitlyEnabled_ReturnsWarning()
    {
        var options = new CertusOptions
        {
            CaConnectionString = null,
            UseMockCa = true,
            ExternalUrl = "https://certus.example.com",
        };

        var warnings = CreateValidator(options).Validate();

        warnings.Should().Be(1, "the mock warning replaces the unconfigured warning");
    }

    [Fact]
    public void Validate_MockCaTogetherWithRealCa_Throws()
    {
        var options = FullyConfigured();
        options.UseMockCa = true;

        var act = () => CreateValidator(options).Validate();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*UseMockCa*CaConnectionString*mutually exclusive*");
    }

    [Fact]
    public void Validate_NoExternalUrl_ReturnsWarning()
    {
        var options = new CertusOptions
        {
            CaConnectionString = "ca\\TestCA",
            ExternalUrl = null,
        };

        var warnings = CreateValidator(options).Validate();

        warnings.Should().BeGreaterThan(0);
    }

    [Fact]
    public void Validate_HttpExternalUrl_ReturnsWarning()
    {
        var options = new CertusOptions
        {
            CaConnectionString = "ca\\TestCA",
            ExternalUrl = "http://certus.example.com",
        };

        var warnings = CreateValidator(options).Validate();

        warnings.Should().BeGreaterThan(0);
    }

    [Fact]
    public void Validate_InMemoryDatabase_ReturnsWarning()
    {
        var options = new CertusOptions
        {
            CaConnectionString = "ca\\TestCA",
            ExternalUrl = "https://certus.example.com",
            DatabasePath = ":memory:",
        };

        var warnings = CreateValidator(options).Validate();

        warnings.Should().BeGreaterThan(0);
    }

    [Fact]
    public void Validate_ZeroSyncInterval_ReturnsWarning()
    {
        var options = new CertusOptions
        {
            CaConnectionString = "ca\\TestCA",
            ExternalUrl = "https://certus.example.com",
            SyncIntervalMinutes = 0,
        };

        var warnings = CreateValidator(options).Validate();

        warnings.Should().BeGreaterThan(0);
    }

    [Fact]
    public void Validate_AuthDisabledWithRealCa_Throws()
    {
        var auth = new AuthOptions { Mode = AuthOptions.ModeDisabled };

        var act = () => CreateValidator(FullyConfigured(), auth).Validate();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*Auth:Mode=Disabled*CaConnectionString*");
    }

    [Fact]
    public void Validate_AuthDisabledWithoutCa_WarnsButDoesNotThrow()
    {
        var options = new CertusOptions
        {
            CaConnectionString = null,
            ExternalUrl = "https://certus.example.com",
            DatabasePath = "C:\\ProgramData\\Certus\\certus.db",
        };
        var auth = new AuthOptions { Mode = AuthOptions.ModeDisabled };

        var warnings = CreateValidator(options, auth).Validate();

        warnings.Should().BeGreaterThan(0);
    }

    [Fact]
    public void Validate_RequireHttpsOff_ReturnsWarning()
    {
        var auth = new AuthOptions { RequireHttps = false };

        var warnings = CreateValidator(FullyConfigured(), auth).Validate();

        warnings.Should().Be(1);
    }

    [Fact]
    public void Validate_UnresolvableAdminGroup_ReturnsWarning()
    {
        var auth = new AuthOptions { AdminGroup = "CERTUS_NO_SUCH_GROUP_8f3a1c" };

        var warnings = CreateValidator(FullyConfigured(), auth).Validate();

        warnings.Should().Be(1);
    }

    [Fact]
    public void Validate_ResolvableAdminGroup_ReturnsZeroWarnings()
    {
        var auth = new AuthOptions { AdminGroup = @"BUILTIN\Administrators" };

        var warnings = CreateValidator(FullyConfigured(), auth).Validate();

        warnings.Should().Be(0);
    }

    [Fact]
    public void Validate_RateLimitNonPositiveLimit_ReturnsWarning()
    {
        var rateLimit = new AcmeRateLimitOptions { NewOrderLimit = 0 };

        var warnings = CreateValidator(FullyConfigured(), rateLimitOptions: rateLimit).Validate();

        warnings.Should().Be(1);
    }

    [Fact]
    public void Validate_RateLimitZeroWindow_ReturnsWarning()
    {
        var rateLimit = new AcmeRateLimitOptions { WindowSeconds = 0 };

        var warnings = CreateValidator(FullyConfigured(), rateLimitOptions: rateLimit).Validate();

        warnings.Should().Be(1);
    }

    [Fact]
    public void Validate_RateLimitDisabledWithBadValues_AddsNoWarning()
    {
        var rateLimit = new AcmeRateLimitOptions
        {
            Enabled = false,
            NewAccountLimit = 0,
            NewOrderLimit = -5,
            GeneralLimit = 0,
            WindowSeconds = 0,
        };

        var warnings = CreateValidator(FullyConfigured(), rateLimitOptions: rateLimit).Validate();

        warnings.Should().Be(0);
    }

    [Fact]
    public void Validate_InvalidTrustedProxy_ReturnsWarning()
    {
        var auth = new AuthOptions { TrustedProxies = ["not-an-ip"] };

        var warnings = CreateValidator(FullyConfigured(), auth).Validate();

        warnings.Should().Be(1);
    }

    [Fact]
    public void Validate_ValidTrustedProxies_ReturnsZeroWarnings()
    {
        var auth = new AuthOptions { TrustedProxies = ["10.0.0.5", "::1"] };

        var warnings = CreateValidator(FullyConfigured(), auth).Validate();

        warnings.Should().Be(0);
    }

    [Fact]
    public void Validate_UnknownAuthMode_ReturnsWarning()
    {
        var auth = new AuthOptions { Mode = "Kerberos" };

        var warnings = CreateValidator(FullyConfigured(), auth).Validate();

        warnings.Should().Be(1);
    }

    /// <summary>
    /// Build a configuration from real appsettings.json and settings.json
    /// files in a temp directory, so the layer inspector classifies the
    /// providers the way both hosts wire them.
    /// </summary>
    private static IConfiguration LayeredConfiguration(
        string tempDir, string appSettingsJson, string overlayJson)
    {
        File.WriteAllText(Path.Combine(tempDir, "appsettings.json"), appSettingsJson);
        File.WriteAllText(Path.Combine(tempDir, CertusPaths.SettingsOverlayFileName), overlayJson);

        var config = new ConfigurationManager();
        config.SetBasePath(tempDir);
        config.AddJsonFile("appsettings.json", optional: false);
        ((IConfigurationBuilder)config).AddSettingsOverlay(tempDir);
        return config;
    }

    [Fact]
    public void Validate_AppSettingsUrlOverriddenByOverlay_ReturnsWarning()
    {
        var tempDir = Directory.CreateTempSubdirectory("certus-validator-").FullName;
        try
        {
            var config = LayeredConfiguration(
                tempDir,
                """{ "Certus": { "ExternalUrl": "https://from-appsettings.example.com" } }""",
                """{ "Certus": { "ExternalUrl": "https://certus.example.com" } }""");

            var warnings = CreateValidator(FullyConfigured(), configuration: config).Validate();

            warnings.Should().Be(1, "the overridden appsettings value is the only warning");
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void Validate_AppSettingsNullUrlUnderOverlay_AddsNoWarning()
    {
        var tempDir = Directory.CreateTempSubdirectory("certus-validator-").FullName;
        try
        {
            // The shipped appsettings.json carries ExternalUrl as an explicit
            // JSON null; an overlay value on top of that is normal operation,
            // not an override worth warning about.
            var config = LayeredConfiguration(
                tempDir,
                """{ "Certus": { "ExternalUrl": null } }""",
                """{ "Certus": { "ExternalUrl": "https://certus.example.com" } }""");

            var warnings = CreateValidator(FullyConfigured(), configuration: config).Validate();

            warnings.Should().Be(0);
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }
}

using Certus.Core.Configuration;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NSubstitute;

namespace Certus.Core.Tests.Configuration;

/// <summary>
/// The instance mode switch (issue #470). Monitor mode is an explicit opt in, so absence
/// means full, and a value that is there but is neither word is refused rather than read
/// as either: reading it as full would silently re-enable issuance on a CA whose team
/// was promised none.
/// </summary>
public class CertusInstanceModeTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Parse_NothingThere_IsFull(string? value)
    {
        var mode = CertusInstanceMode.Parse(value, "test");

        mode.Mode.Should().Be(InstanceMode.Full);
        mode.InvalidReason.Should().BeNull();
        mode.WireName.Should().Be("full");
    }

    [Theory]
    [InlineData("monitor")]
    [InlineData("MONITOR")]
    [InlineData("  Monitor\t")]
    public void Parse_Monitor_IgnoringCaseAndSurroundingSpace(string value)
    {
        var mode = CertusInstanceMode.Parse(value, "test");

        mode.Mode.Should().Be(InstanceMode.Monitor);
        mode.IsMonitor.Should().BeTrue();
        mode.InvalidReason.Should().BeNull();
        mode.WireName.Should().Be("monitor");
    }

    [Theory]
    [InlineData("full")]
    [InlineData("Full")]
    [InlineData(" FULL ")]
    public void Parse_Full_IgnoringCaseAndSurroundingSpace(string value)
    {
        var mode = CertusInstanceMode.Parse(value, "test");

        mode.Mode.Should().Be(InstanceMode.Full);
        mode.InvalidReason.Should().BeNull();
    }

    [Theory]
    [InlineData("monitr")]
    [InlineData("1")]
    [InlineData("true")]
    [InlineData("monitor-only")]
    [InlineData("read only")]
    public void Parse_AnythingElse_IsRefusedAndRegistersAsMonitor(string value)
    {
        var mode = CertusInstanceMode.Parse(value, "test");

        mode.InvalidReason.Should().NotBeNull().And.Contain(value.Trim());
        // Whatever runs before the startup refusal must never write to the CA.
        mode.IsMonitor.Should().BeTrue();
    }

    [Fact]
    public void Parse_EchoesARefusedValue_WithoutItsControlCharacters_AndBounded()
    {
        var forged = "monitr\r\n2026-10-10 [INF] Full mode" + new string('x', 500);

        var reason = CertusInstanceMode.Parse(forged, "test").InvalidReason!;

        reason.Should().NotContain("\r").And.NotContain("\n");
        reason.Length.Should().BeLessThan(200);
    }

    [Theory]
    [InlineData(null, InstanceMode.Full)]
    [InlineData("monitor", InstanceMode.Monitor)]
    [InlineData("full", InstanceMode.Full)]
    public void FromRegistryValue_AString_IsParsed(string? raw, InstanceMode expected)
    {
        var mode = CertusInstanceMode.FromRegistryValue(raw, readError: null);

        mode.Mode.Should().Be(expected);
        mode.InvalidReason.Should().BeNull();
        mode.Source.Should().Be(CertusInstanceMode.RegistrySource);
    }

    public static TheoryData<object, string> NonStringValues => new()
    {
        // REG_DWORD 1 is what an installer checkbox most naturally writes; read "as
        // string" it would have been absent, so full mode.
        { 1, "REG_DWORD" },
        { 1L, "REG_QWORD" },
        { new[] { "monitor" }, "REG_MULTI_SZ" },
        { new byte[] { 1 }, "REG_BINARY" },
    };

    [Theory]
    [MemberData(nameof(NonStringValues))]
    public void FromRegistryValue_NotAString_IsRefusedRatherThanReadAsAbsent(object raw, string kind)
    {
        var mode = CertusInstanceMode.FromRegistryValue(raw, readError: null);

        mode.InvalidReason.Should().Contain(kind).And.Contain("REG_SZ");
        mode.IsMonitor.Should().BeTrue();
    }

    [Fact]
    public void FromRegistryValue_AReadThatFailed_IsRefusedRatherThanReadAsAbsent()
    {
        var mode = CertusInstanceMode.FromRegistryValue(null, readError: "Access is denied.");

        mode.InvalidReason.Should().Contain("could not be read").And.Contain("Access is denied.");
        mode.IsMonitor.Should().BeTrue();
    }

    [Fact]
    public void Development_ReadsTheDevelopmentKey()
    {
        var mode = CertusInstanceMode.Resolve(Config("monitor"), Env(Environments.Development));

        mode.IsMonitor.Should().BeTrue();
        mode.Source.Should().Be(CertusInstanceMode.DevelopmentKey);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Development_WithNothingConfigured_FallsBackToTheRegistry(string? value)
    {
        // A monitor mode install started in Development must stay in monitor mode, so
        // an unset key is not "full": the registry answers, as for any other host.
        var mode = CertusInstanceMode.Resolve(Config(value), Env(Environments.Development));

        mode.Source.Should().Be(CertusInstanceMode.RegistrySource);
    }

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    [InlineData("development-ish")]
    public void AnyOtherEnvironment_IgnoresTheKey_AndReadsTheRegistry(string environment)
    {
        var mode = CertusInstanceMode.Resolve(Config("monitor"), Env(environment));

        // What the registry says depends on the machine; that it was the one asked does not.
        mode.Source.Should().Be(CertusInstanceMode.RegistrySource);
    }

    [Fact]
    public void LogAtStartup_Monitor_WarnsSoItStandsOut()
    {
        var logger = Substitute.For<ILogger>();
        logger.IsEnabled(Arg.Any<LogLevel>()).Returns(true);

        CertusInstanceMode.Monitor.LogAtStartup(logger);

        logger.ReceivedCalls().Should().Contain(c =>
            c.GetMethodInfo().Name == nameof(ILogger.Log)
            && (LogLevel)c.GetArguments()[0]! == LogLevel.Warning);
    }

    private static IConfiguration Config(string? value) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { [CertusInstanceMode.DevelopmentKey] = value })
            .Build();

    private static IHostEnvironment Env(string name) => new TestEnvironment { EnvironmentName = name };

    private sealed class TestEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Production;

        public string ApplicationName { get; set; } = "Certus.Core.Tests";

        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;

        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}

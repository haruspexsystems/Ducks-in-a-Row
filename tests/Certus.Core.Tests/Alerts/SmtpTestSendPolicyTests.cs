using Certus.Core.Alerts;

namespace Certus.Core.Tests.Alerts;

/// <summary>
/// The stored SMTP password goes only to the relay it was saved for (issue
/// #635, CRA R09). A candidate test that omits the password and aims
/// anywhere else is refused before anything connects.
/// </summary>
public class SmtpTestSendPolicyTests
{
    private static SmtpOptions Relay(
        string host = "relay.example.com", int port = 587, SmtpTlsMode? tls = SmtpTlsMode.StartTls, bool useSsl = true) =>
        new() { Host = host, Port = port, TlsMode = tls, UseSsl = useSsl };

    [Fact]
    public void SameRelay_StoredPasswordMayBeUsed()
    {
        SmtpTestSendPolicy.Refuse(Relay(), passwordTyped: false, storedPasswordExists: true, Relay())
            .Should().BeNull();
    }

    [Fact]
    public void SameRelay_HostComparedWithoutCase()
    {
        SmtpTestSendPolicy.Refuse(Relay(host: "RELAY.example.com "), false, true, Relay())
            .Should().BeNull();
    }

    [Theory]
    [InlineData("smtp.attacker.example", 587, SmtpTlsMode.StartTls)]
    [InlineData("relay.example.com", 2525, SmtpTlsMode.StartTls)]
    [InlineData("relay.example.com", 587, SmtpTlsMode.None)]
    public void DifferentHostPortOrTlsMode_WithoutATypedPassword_IsRefused(string host, int port, SmtpTlsMode tls)
    {
        SmtpTestSendPolicy.Refuse(Relay(host, port, tls), false, true, Relay())
            .Should().Be(SmtpTestSendPolicy.Refusal);
    }

    [Fact]
    public void DifferentRelay_WithATypedPassword_Proceeds()
    {
        SmtpTestSendPolicy.Refuse(Relay(host: "smtp.attacker.example", tls: SmtpTlsMode.None), passwordTyped: true, true, Relay())
            .Should().BeNull();
    }

    [Fact]
    public void NoStoredPassword_NothingToProtect_Proceeds()
    {
        SmtpTestSendPolicy.Refuse(Relay(host: "smtp.attacker.example"), false, storedPasswordExists: false, Relay())
            .Should().BeNull();
    }

    [Fact]
    public void NoSavedRelayAtAll_StoredPasswordIsNotSentToTheFirstHostNamed()
    {
        SmtpTestSendPolicy.Refuse(Relay(), false, true, saved: null)
            .Should().Be(SmtpTestSendPolicy.Refusal);
    }

    /// <summary>
    /// An install configured before the explicit mode existed has no TLS mode
    /// saved; what the transport does is derived from UseSsl and the port, and
    /// the comparison answers for that, not for the null.
    /// </summary>
    [Theory]
    [InlineData(465, SmtpTlsMode.Implicit, true)]
    [InlineData(587, SmtpTlsMode.StartTls, true)]
    [InlineData(587, SmtpTlsMode.None, false)]
    [InlineData(465, SmtpTlsMode.StartTls, false)]
    public void LegacyDerivedTlsMode_IsComparedAsTheTransportWouldUseIt(int port, SmtpTlsMode candidateMode, bool same)
    {
        var saved = Relay(port: port, tls: null, useSsl: true);
        var candidate = Relay(port: port, tls: candidateMode);

        var refusal = SmtpTestSendPolicy.Refuse(candidate, false, true, saved);

        if (same)
            refusal.Should().BeNull();
        else
            refusal.Should().Be(SmtpTestSendPolicy.Refusal);
    }
}

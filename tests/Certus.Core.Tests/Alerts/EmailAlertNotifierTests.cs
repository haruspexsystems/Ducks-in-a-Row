using Certus.Core.Alerts;
using Certus.Core.Security;
using MailKit.Security;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Certus.Core.Tests.Alerts;

public class EmailAlertNotifierTests
{
    private static ExpiryAlertBatch CreateTestBatch(int thresholdDays = 30) => new(
        thresholdDays,
        [
            new CertificateExpiryInfo(1, "CN=test.example.com", "SERIAL001", "WebServer",
                DateTime.UtcNow.AddDays(25), 25)
        ]);

    /// <summary>
    /// The same prefix scheme as the EAB tests' fake: recognisable blobs
    /// unprotect, anything else reports the keyring-mismatch null.
    /// </summary>
    private sealed class FakeSecretProtector : ISecretProtector
    {
        private const string Prefix = "protected:";

        public string Protect(string plaintext) => Prefix + plaintext;

        public string? TryUnprotect(string protectedValue) =>
            protectedValue.StartsWith(Prefix, StringComparison.Ordinal)
                ? protectedValue[Prefix.Length..]
                : null;
    }

    private static EmailAlertNotifier CreateNotifier(SmtpOptions? smtp) =>
        new(Options.Create(new AlertOptions { Smtp = smtp }),
            new FakeSecretProtector(),
            NullLogger<EmailAlertNotifier>.Instance);

    [Theory]
    [InlineData(false, 587, SecureSocketOptions.None)]
    [InlineData(false, 465, SecureSocketOptions.None)]
    [InlineData(false, 25, SecureSocketOptions.None)]
    [InlineData(true, 465, SecureSocketOptions.SslOnConnect)]
    [InlineData(true, 587, SecureSocketOptions.StartTls)]
    [InlineData(true, 25, SecureSocketOptions.StartTls)]
    [InlineData(true, 2525, SecureSocketOptions.StartTls)]
    public void ResolveSocketOptions_MapsByPortAndUseSsl(bool useSsl, int port, SecureSocketOptions expected)
    {
        EmailAlertNotifier.ResolveSocketOptions(useSsl, port).Should().Be(expected);
    }

    [Theory]
    [InlineData(SmtpTlsMode.None, 465, SecureSocketOptions.None)]
    [InlineData(SmtpTlsMode.Implicit, 587, SecureSocketOptions.SslOnConnect)]
    [InlineData(SmtpTlsMode.StartTls, 465, SecureSocketOptions.StartTls)]
    public void ResolveSocketOptions_ExplicitModeBeatsTheDerivation(
        SmtpTlsMode mode, int port, SecureSocketOptions expected)
    {
        // Each case picks a port whose legacy derivation would answer
        // differently, so a regression to port sniffing fails the test.
        var smtp = new SmtpOptions { Port = port, UseSsl = true, TlsMode = mode };

        EmailAlertNotifier.ResolveSocketOptions(smtp).Should().Be(expected);
    }

    [Fact]
    public void ResolveSocketOptions_WithoutAMode_FallsBackToTheDerivation()
    {
        var smtp = new SmtpOptions { Port = 465, UseSsl = true, TlsMode = null };

        EmailAlertNotifier.ResolveSocketOptions(smtp).Should().Be(SecureSocketOptions.SslOnConnect);
    }

    [Theory]
    [InlineData("535 authentication failed for user with hunter42", "hunter42",
        "535 authentication failed for user with (redacted)")]
    [InlineData("timed out", "hunter42", "timed out")]
    [InlineData("weak pw1 leaked", "pw1", "weak pw1 leaked")]
    public void ScrubResolvedPassword_StripsTheResolvedValueOnly(
        string message, string password, string expected)
    {
        // The redactor's secrets pool cannot know a password decrypted from
        // the protected blob, so the notifier scrubs it at the source. Below
        // four characters the redactor's own minimum length rule applies.
        EmailAlertNotifier.ScrubResolvedPassword(message, password).Should().Be(expected);
    }

    [Fact]
    public void ScrubResolvedPassword_NullSafeInBothDirections()
    {
        EmailAlertNotifier.ScrubResolvedPassword(null, "hunter42").Should().BeNull();
        EmailAlertNotifier.ScrubResolvedPassword("a message", null).Should().Be("a message");
    }

    [Fact]
    public async Task Send_WithUndecryptableStoredPassword_FailsClosedBeforeConnecting()
    {
        // A restored data directory cannot decrypt the blob (DPAPI machine
        // scope). Falling back to plaintext or sending unauthenticated would
        // both be worse than failing with the recovery in the message. The
        // host below does not resolve, so a result carrying this message
        // proves the send stopped before any connection was attempted.
        var sut = CreateNotifier(new SmtpOptions
        {
            Host = "smtp.example.invalid",
            FromAddress = "ducks@example.com",
            Recipients = ["admin@example.com"],
            Username = "relay-user",
            PasswordProtected = "not-a-blob-this-keyring-knows",
        });

        var result = await sut.SendTestAlertAsync(new TestAlert("CONTOSO\\alice", DateTime.UtcNow));

        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().Contain("could not be read on this machine");
        result.ErrorMessage.Should().Contain("Settings page");
    }

    [Fact]
    public void IsEnabled_WithoutSmtp_ReturnsFalse()
    {
        var sut = CreateNotifier(null);

        sut.IsEnabled.Should().BeFalse();
    }

    [Fact]
    public void IsEnabled_WithoutHost_ReturnsFalse()
    {
        var sut = CreateNotifier(new SmtpOptions
        {
            Host = "",
            Recipients = ["admin@example.com"]
        });

        sut.IsEnabled.Should().BeFalse();
    }

    [Fact]
    public void IsEnabled_WithoutRecipients_ReturnsFalse()
    {
        var sut = CreateNotifier(new SmtpOptions
        {
            Host = "smtp.example.com",
            Recipients = []
        });

        sut.IsEnabled.Should().BeFalse();
    }

    [Fact]
    public void IsEnabled_WithHostSenderAndRecipients_ReturnsTrue()
    {
        var sut = CreateNotifier(new SmtpOptions
        {
            Host = "smtp.example.com",
            FromAddress = "ducks@example.com",
            Recipients = ["admin@example.com"]
        });

        sut.IsEnabled.Should().BeTrue();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void IsEnabled_WithBlankSender_ReturnsFalse(string? fromAddress)
    {
        // The property initializer default only survives when the key is
        // absent; an explicit null or empty Smtp:FromAddress in
        // appsettings.json overwrites it through the configuration binder,
        // and a message with no sender cannot be built (issue #209).
        var sut = CreateNotifier(new SmtpOptions
        {
            Host = "smtp.example.com",
            FromAddress = fromAddress!,
            Recipients = ["admin@example.com"]
        });

        sut.IsEnabled.Should().BeFalse();
    }

    [Fact]
    public async Task SendExpiryAlert_WhenNotConfigured_ReturnsFailure()
    {
        var sut = CreateNotifier(null);

        var result = await sut.SendExpiryAlertAsync(CreateTestBatch());

        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().Be("SMTP not configured");
    }

    [Fact]
    public async Task SendTestAlert_WhenNotConfigured_ReturnsFailure()
    {
        var sut = CreateNotifier(null);

        var result = await sut.SendTestAlertAsync(new TestAlert("CONTOSO\\alice", DateTime.UtcNow));

        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().Be("SMTP not configured");
    }

    [Fact]
    public async Task SendTestAlert_WhenAllRecipientsMalformed_ReturnsFailure()
    {
        var sut = CreateNotifier(new SmtpOptions
        {
            Host = "smtp.example.com",
            Recipients = ["not an email"]
        });

        var result = await sut.SendTestAlertAsync(new TestAlert("CONTOSO\\alice", DateTime.UtcNow));

        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().Be("No valid recipient addresses");
    }

    [Theory]
    [InlineData("expiry")]
    [InlineData("server")]
    [InlineData("test")]
    public async Task Send_WhenBuildingTheMessageThrows_ReturnsFailureRatherThanThrowing(string kind)
    {
        // A notifier never throws by contract. ExpiryMonitorService has no per
        // notifier try/catch and would abandon a whole threshold pass before
        // writing its AlertsSent rows, and AlertTestService states the contract
        // outright. A null sender used to be the way to reach the builder
        // throw, but IsEnabled now short circuits that state by design
        // (issue #209); a malformed sender still passes the presence check and
        // detonates in MimeKit's MailboxAddress constructor inside the
        // builder, which is the path this test pins.
        var sut = CreateNotifier(new SmtpOptions
        {
            Host = "smtp.example.com",
            Recipients = ["admin@example.com"],
            FromAddress = "not an address",
        });

        var result = kind switch
        {
            "expiry" => await sut.SendExpiryAlertAsync(CreateTestBatch()),
            "server" => await sut.SendServerCertificateAlertAsync(new ServerCertificateAlert("denied")),
            _ => await sut.SendTestAlertAsync(new TestAlert("CONTOSO\\alice", DateTime.UtcNow)),
        };

        result.Success.Should().BeFalse();
        // The message construction failure specifically, not a network error.
        // The host does not resolve either, so a looser assertion would pass
        // whether or not the builder ran inside the try. MimeKit reports a
        // malformed sender as an invalid addr-spec token.
        result.ErrorMessage.Should().Contain("addr");
    }

    [Fact]
    public void BuildTestMessage_SubjectCarriesTheTestMarkerFirst()
    {
        // TEST leads rather than sitting in the urgency slot, where CRITICAL and
        // WARNING already live, and the [Ducks in a Row ...] prefix is kept so an
        // inbox rule written to catch alerts still catches this one.
        var message = BuildTest();

        message.Subject.Should().StartWith("[Ducks in a Row TEST]");
        message.Subject.Should().NotContain("expiring");
    }

    [Fact]
    public void BuildTestMessage_BodySaysNoCertificateIsExpiring()
    {
        var body = ((MimeKit.TextPart)BuildTest().Body!).Text!;

        body.Should().Contain("This is a test");
        body.Should().Contain("No certificate is expiring");
        // A recipient must not read a delivered test as proof that monitoring is
        // running: AlertOptions.Enabled gates the monitor, not the notifiers.
        body.Should().Contain("does not mean expiry monitoring is");
    }

    [Fact]
    public void BuildTestMessage_CarriesTheAlertKindHeaderAndTheActor()
    {
        var message = BuildTest();

        message.Headers["X-Certus-Alert-Kind"].Should().Be("test");
        ((MimeKit.TextPart)message.Body!).Text!.Should().Contain("CONTOSO\\alice");
    }

    private static MimeKit.MimeMessage BuildTest()
    {
        var smtp = new SmtpOptions { Host = "smtp.example.com", Recipients = ["admin@example.com"] };
        var recipients = EmailAlertNotifier.ParseRecipients(smtp.Recipients, out _);

        return EmailAlertNotifier.BuildTestMessage(
            new TestAlert("CONTOSO\\alice", new DateTime(2026, 8, 1, 12, 0, 0, DateTimeKind.Utc)),
            smtp, recipients);
    }

    [Fact]
    public void ParseRecipients_AllValid_KeepsAllAndReportsNoneInvalid()
    {
        var result = EmailAlertNotifier.ParseRecipients(
            ["admin@example.com", "ops@example.com"], out var invalid);

        result.Select(a => a.Address).Should().Equal("admin@example.com", "ops@example.com");
        invalid.Should().BeEmpty();
    }

    [Fact]
    public void ParseRecipients_MixedValidAndMalformed_PartitionsThem()
    {
        var result = EmailAlertNotifier.ParseRecipients(
            ["good@example.com", "not an email", "also.good@example.com"], out var invalid);

        result.Select(a => a.Address).Should().Equal("good@example.com", "also.good@example.com");
        invalid.Should().ContainSingle().Which.Should().Be("not an email");
    }

    [Fact]
    public void ParseRecipients_AllMalformed_ReturnsEmptyAndReportsAllInvalid()
    {
        var result = EmailAlertNotifier.ParseRecipients(
            ["not an email", ""], out var invalid);

        result.Should().BeEmpty();
        invalid.Should().HaveCount(2);
    }

    [Fact]
    public async Task SendExpiryAlert_WhenAllRecipientsMalformed_ReturnsFailure()
    {
        var sut = CreateNotifier(new SmtpOptions
        {
            Host = "smtp.example.com",
            Recipients = ["not an email"]
        });

        var result = await sut.SendExpiryAlertAsync(CreateTestBatch());

        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().Be("No valid recipient addresses");
    }
}

using Certus.Core.Alerts;
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

    private static EmailAlertNotifier CreateNotifier(SmtpOptions? smtp) =>
        new(Options.Create(new AlertOptions { Smtp = smtp }),
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
    public void IsEnabled_WithHostAndRecipients_ReturnsTrue()
    {
        var sut = CreateNotifier(new SmtpOptions
        {
            Host = "smtp.example.com",
            Recipients = ["admin@example.com"]
        });

        sut.IsEnabled.Should().BeTrue();
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

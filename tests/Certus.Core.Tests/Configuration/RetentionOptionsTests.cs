using Certus.Core.Configuration;
using Microsoft.Extensions.Configuration;

namespace Certus.Core.Tests.Configuration;

/// <summary>
/// The retention periods (issue #637): Sean's defaults of 2026-10-21 are what
/// the code starts from, the section binds, 0 disables a class, and the batch
/// size never reaches zero.
/// </summary>
public class RetentionOptionsTests
{
    [Fact]
    public void Defaults_AreTheDecidedPeriods()
    {
        var options = new RetentionOptions();

        options.FinishedOrderDays.Should().Be(90);
        options.DeactivatedAccountDays.Should().Be(365);
        options.AlertHistoryDays.Should().Be(730);
        options.AuditTrailDays.Should().Be(730);
        options.EffectiveAuditTrailDays.Should().Be(730);
        options.EffectiveBatchSize.Should().Be(RetentionOptions.DefaultBatchSize);
        options.EverythingDisabled.Should().BeFalse();
    }

    // ---- The audit trail floor (issue #634) ----

    [Theory]
    [InlineData(730, 730, false)]
    [InlineData(3650, 3650, false)]
    [InlineData(90, 90, false)]
    [InlineData(89, 90, true)]
    [InlineData(1, 90, true)]
    public void AuditTrailDays_NeverDropsBelowTheFloor_WhileOn(int configured, int effective, bool raised)
    {
        var options = new RetentionOptions { AuditTrailDays = configured };

        options.EffectiveAuditTrailDays.Should().Be(effective);
        options.AuditTrailRaisedToFloor.Should().Be(raised);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void AuditTrailDays_ZeroOrLess_TurnsTheClassOff_WithoutTheFloor(int configured)
    {
        var options = new RetentionOptions { AuditTrailDays = configured };

        options.EffectiveAuditTrailDays.Should().Be(0);
        options.AuditTrailRaisedToFloor.Should().BeFalse();
        RetentionOptions.IsEnabled(options.EffectiveAuditTrailDays).Should().BeFalse();
    }

    [Fact]
    public void AuditTrailDays_Binds_FromTheRetentionSection()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Certus:Retention:AuditTrailDays"] = "45",
            })
            .Build();

        var options = configuration.GetSection(RetentionOptions.SectionName).Get<RetentionOptions>()!;

        options.AuditTrailDays.Should().Be(45);
        options.EffectiveAuditTrailDays.Should().Be(RetentionOptions.AuditTrailFloorDays);
    }

    [Fact]
    public void Binds_FromTheRetentionSection()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Certus:Retention:FinishedOrderDays"] = "30",
                ["Certus:Retention:DeactivatedAccountDays"] = "0",
                ["Certus:Retention:AlertHistoryDays"] = "3650",
            })
            .Build();

        var options = configuration.GetSection(RetentionOptions.SectionName).Get<RetentionOptions>()!;

        options.FinishedOrderDays.Should().Be(30);
        options.DeactivatedAccountDays.Should().Be(0);
        options.AlertHistoryDays.Should().Be(3650);
    }

    [Theory]
    [InlineData(0, false)]
    [InlineData(-5, false)]
    [InlineData(1, true)]
    public void IsEnabled_IsAPositiveNumberOfDays(int days, bool enabled)
    {
        RetentionOptions.IsEnabled(days).Should().Be(enabled);
    }

    [Fact]
    public void EverythingDisabled_WhenEveryPeriodIsZero()
    {
        new RetentionOptions { FinishedOrderDays = 0, DeactivatedAccountDays = 0, AlertHistoryDays = 0, AuditTrailDays = 0 }
            .EverythingDisabled.Should().BeTrue();
        new RetentionOptions { FinishedOrderDays = 0, DeactivatedAccountDays = 0, AlertHistoryDays = 1, AuditTrailDays = 0 }
            .EverythingDisabled.Should().BeFalse();
        new RetentionOptions { FinishedOrderDays = 0, DeactivatedAccountDays = 0, AlertHistoryDays = 0 }
            .EverythingDisabled.Should().BeFalse("the audit trail is a retention class too");
    }

    [Theory]
    [InlineData(0, 1)]
    [InlineData(-10, 1)]
    [InlineData(250, 250)]
    public void EffectiveBatchSize_NeverDropsBelowOne(int configured, int effective)
    {
        new RetentionOptions { BatchSize = configured }.EffectiveBatchSize.Should().Be(effective);
    }
}

using Certus.Core.Alerts;
using Microsoft.Extensions.Configuration;

namespace Certus.Core.Tests.Alerts;

/// <summary>
/// Tests for the threshold normalization. Regression cover for the duplicated
/// thresholds log line ("30d, 14d, 7d, 1d, 30d, 14d, 7d, 1d"): the
/// configuration binder appends bound array elements onto the property's
/// existing value, so a C# initializer default plus the same array in
/// appsettings yielded every threshold twice. The initializer is now empty and
/// the defaults are applied by NormalizeThresholdDays via PostConfigure.
/// </summary>
public class AlertOptionsTests
{
    [Fact]
    public void Normalize_NoConfiguredThresholds_AppliesDefaults()
    {
        var options = new AlertOptions();

        options.NormalizeThresholdDays();

        options.ThresholdDays.Should().Equal(30, 14, 7, 1);
    }

    [Fact]
    public void Normalize_DuplicatedThresholds_DedupsToOnePass()
    {
        var options = new AlertOptions { ThresholdDays = [30, 14, 7, 1, 30, 14, 7, 1] };

        options.NormalizeThresholdDays();

        options.ThresholdDays.Should().Equal(30, 14, 7, 1);
    }

    [Fact]
    public void Normalize_SortsDescendingAndDropsNonPositiveValues()
    {
        var options = new AlertOptions { ThresholdDays = [1, 7, 99, 7, 0, -3] };

        options.NormalizeThresholdDays();

        options.ThresholdDays.Should().Equal(99, 7, 1);
    }

    [Fact]
    public void Binding_ConfiguredArray_FullyReplacesTheDefaults()
    {
        // With the empty initializer, binding yields exactly the configured
        // values: nothing left over for the binder to append onto.
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Certus:Alerts:ThresholdDays:0"] = "21",
                ["Certus:Alerts:ThresholdDays:1"] = "3",
            })
            .Build();

        var options = new AlertOptions();
        config.GetSection(AlertOptions.SectionName).Bind(options);
        options.NormalizeThresholdDays();

        options.ThresholdDays.Should().Equal(21, 3);
    }
}

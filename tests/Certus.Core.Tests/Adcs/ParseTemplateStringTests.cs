using Certus.Adcs;

namespace Certus.Core.Tests.Adcs;

/// <summary>
/// Tests for AdcsClient.ParseTemplateString — verifies correct parsing
/// of the CR_PROP_TEMPLATES string format from ADCS.
/// </summary>
public class ParseTemplateStringTests
{
    [Fact]
    public void ParseTemplateString_ValidPairs_ParsesCorrectly()
    {
        var raw = "WebServer\n1.3.6.1.4.1.311.21.8.1\nMachine\n1.3.6.1.4.1.311.21.8.2\n";

        var result = AdcsClient.ParseTemplateString(raw);

        result.Should().HaveCount(2);
        result[0].Name.Should().Be("WebServer");
        result[0].Oid.Should().Be("1.3.6.1.4.1.311.21.8.1");
        result[1].Name.Should().Be("Machine");
        result[1].Oid.Should().Be("1.3.6.1.4.1.311.21.8.2");
    }

    [Fact]
    public void ParseTemplateString_SingleTemplate_Works()
    {
        var raw = "CodeSigning\n1.3.6.1.4.1.311.21.8.3\n";

        var result = AdcsClient.ParseTemplateString(raw);

        result.Should().HaveCount(1);
        result[0].Name.Should().Be("CodeSigning");
    }

    [Fact]
    public void ParseTemplateString_EmptyString_ReturnsEmpty()
    {
        var result = AdcsClient.ParseTemplateString("");
        result.Should().BeEmpty();
    }

    [Fact]
    public void ParseTemplateString_Null_ReturnsEmpty()
    {
        var result = AdcsClient.ParseTemplateString(null!);
        result.Should().BeEmpty();
    }

    [Fact]
    public void ParseTemplateString_OddNumberOfLines_IgnoresTrailing()
    {
        var raw = "WebServer\n1.3.6.1.4.1.311.21.8.1\nOrphanName\n";

        var result = AdcsClient.ParseTemplateString(raw);

        // "OrphanName" has no OID pair, so it should be ignored
        result.Should().HaveCount(1);
        result[0].Name.Should().Be("WebServer");
    }

    [Fact]
    public void ParseTemplateString_WithWhitespace_TrimsValues()
    {
        var raw = "  WebServer  \n  1.3.6.1.4.1.311.21.8.1  \n";

        var result = AdcsClient.ParseTemplateString(raw);

        result.Should().HaveCount(1);
        result[0].Name.Should().Be("WebServer");
        result[0].Oid.Should().Be("1.3.6.1.4.1.311.21.8.1");
    }
}

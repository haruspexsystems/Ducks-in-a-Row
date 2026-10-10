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
    [Fact]
    public void ParseTemplateString_OidCarriesAFormatCharacter_PassesItThroughUntouched()
    {
        // The policy for the OID is report, never strip (issue #292). The
        // scan lives in TemplateNameUsability and each surface decides what to
        // say; sanitizing here instead would leave every one of them reporting
        // a value the CA never published, and disagreeing with what certutil
        // shows for the same template.
        //
        // Trim() would not have caught it in any case: a formatting character
        // is not whitespace, and this one is not at an end.
        var softHyphen = char.ConvertFromUtf32(0x00AD);
        var raw = "Contoso\n1.3.6" + softHyphen + ".1.4.1\n";

        var result = AdcsClient.ParseTemplateString(raw);

        result.Should().ContainSingle();
        result[0].Oid.Should().Be("1.3.6" + softHyphen + ".1.4.1");
    }
}

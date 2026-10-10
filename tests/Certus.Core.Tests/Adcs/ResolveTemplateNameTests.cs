using Certus.Adcs;
using Certus.Core.Adcs;

namespace Certus.Core.Tests.Adcs;

/// <summary>
/// Tests for AdcsClient.BuildTemplateDisplayMap and AdcsClient.ResolveTemplateName.
/// The CA database stores the template OID for v2/v3 templates and the
/// programmatic name for v1 templates; both must resolve to the AD display name
/// so the dashboard shows "Web Server ACME" rather than the raw token.
/// </summary>
public class ResolveTemplateNameTests
{
    private static IReadOnlyList<TemplateInfo> SampleTemplates() => new[]
    {
        new TemplateInfo(Name: "WebServerACME", DisplayName: "Web Server ACME", Oid: "1.3.6.1.4.1.311.21.8.15853379.1"),
        new TemplateInfo(Name: "Machine", DisplayName: "Computer", Oid: "1.3.6.1.4.1.311.21.8.15853379.2"),
    };

    [Fact]
    public void BuildTemplateDisplayMap_KeysByBothOidAndProgrammaticName()
    {
        var map = AdcsClient.BuildTemplateDisplayMap(SampleTemplates());

        // OID key (v2/v3 path) resolves to the display name.
        map["1.3.6.1.4.1.311.21.8.15853379.1"].Should().Be("Web Server ACME");
        // Programmatic name key (v1 path) resolves to the same display name.
        map["WebServerACME"].Should().Be("Web Server ACME");
    }

    [Fact]
    public void BuildTemplateDisplayMap_IsCaseInsensitive()
    {
        var map = AdcsClient.BuildTemplateDisplayMap(SampleTemplates());

        map.ContainsKey("webserveracme").Should().BeTrue();
        map["webserveracme"].Should().Be("Web Server ACME");
    }

    [Fact]
    public void BuildTemplateDisplayMap_SkipsEntriesWithBlankDisplayName()
    {
        var templates = new[]
        {
            new TemplateInfo(Name: "NoDisplay", DisplayName: "  ", Oid: "1.3.6.1.4.1.311.21.8.9.1"),
        };

        var map = AdcsClient.BuildTemplateDisplayMap(templates);

        map.Should().BeEmpty();
    }

    [Fact]
    public void ResolveTemplateName_Oid_ReturnsDisplayName()
    {
        var map = AdcsClient.BuildTemplateDisplayMap(SampleTemplates());

        AdcsClient.ResolveTemplateName("1.3.6.1.4.1.311.21.8.15853379.1", map)
            .Should().Be("Web Server ACME");
    }

    [Fact]
    public void ResolveTemplateName_ProgrammaticName_ReturnsDisplayName()
    {
        var map = AdcsClient.BuildTemplateDisplayMap(SampleTemplates());

        AdcsClient.ResolveTemplateName("Machine", map).Should().Be("Computer");
    }

    [Fact]
    public void ResolveTemplateName_UnknownToken_ReturnsRawValue()
    {
        var map = AdcsClient.BuildTemplateDisplayMap(SampleTemplates());

        // A decommissioned template no longer present on the CA falls through
        // unchanged rather than being dropped.
        AdcsClient.ResolveTemplateName("1.3.6.1.4.1.311.21.8.99999.9", map)
            .Should().Be("1.3.6.1.4.1.311.21.8.99999.9");
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public void ResolveTemplateName_EmptyInput_ReturnsEmpty(string? raw)
    {
        var map = AdcsClient.BuildTemplateDisplayMap(SampleTemplates());

        AdcsClient.ResolveTemplateName(raw, map).Should().BeEmpty();
    }

    // ---- The resolved name is sanitized (issue #378) ----------------------
    //
    // Both values this can return are authored outside Ducks: the CA's own row,
    // and a directory read. The strip lives here rather than at the row mapper
    // because that mapper needs a live CA view and no test can reach it.

    [Fact]
    public void ResolveTemplateName_PoisonedRawToken_IsStripped()
    {
        // The unmapped branch, which is the one the issue is about: the map is
        // best effort and falls back to empty on any failure, so the CA's own
        // token is what reaches the database whenever it is unavailable.
        var map = AdcsClient.BuildTemplateDisplayMap(SampleTemplates());
        var rlo = (char)0x202e;

        AdcsClient.ResolveTemplateName("Web" + rlo + "Server", map)
            .Should().Be("WebServer");
    }

    [Fact]
    public void ResolveTemplateName_PoisonedDisplayName_IsStrippedToo()
    {
        // The mapped branch. A display name comes from a directory read, so it
        // is no more ours than the CA's token is, and a strip that covered only
        // the fallback would leave the commoner path open.
        var rlo = (char)0x202e;
        var map = AdcsClient.BuildTemplateDisplayMap(new[]
        {
            new TemplateInfo(
                Name: "WebServerACME",
                DisplayName: "Web" + rlo + " Server ACME",
                Oid: "1.3.6.1.4.1.311.21.8.15853379.1"),
        });

        AdcsClient.ResolveTemplateName("1.3.6.1.4.1.311.21.8.15853379.1", map)
            .Should().Be("Web Server ACME");
    }

    [Fact]
    public void ResolveTemplateName_LooksUpBeforeStripping()
    {
        // The ordering, which is easy to get backwards and silent when wrong.
        // The map is keyed on exactly what the CA stored, so stripping first
        // would miss the entry and return the raw token, losing the display name
        // for precisely the poisoned rows this guards.
        var zwsp = (char)0x200b;
        var poisonedKey = "Web" + zwsp + "ServerACME";
        var map = AdcsClient.BuildTemplateDisplayMap(new[]
        {
            new TemplateInfo(
                Name: poisonedKey,
                DisplayName: "Web Server ACME",
                Oid: "1.3.6.1.4.1.311.21.8.15853379.1"),
        });

        AdcsClient.ResolveTemplateName(poisonedKey, map).Should().Be("Web Server ACME");
    }

    [Fact]
    public void ResolveTemplateName_TokenThatSanitizesAwayEntirely_ReturnsEmpty()
    {
        // Never null: the caller assigns this straight to a required column.
        var map = AdcsClient.BuildTemplateDisplayMap(SampleTemplates());

        AdcsClient.ResolveTemplateName("\u202e\u200b\u2028", map).Should().BeEmpty();
    }
}

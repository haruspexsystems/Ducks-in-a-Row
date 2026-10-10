using Certus.Core.Crl;

namespace Certus.Core.Tests.Crl;

/// <summary>
/// The serverless LDAP URL an ADCS CA writes into every certificate it issues
/// is the shape that has to parse; the rest of RFC 4516 is there so an estate
/// that writes its own does not fall over.
/// </summary>
public class LdapCdpUrlTests
{
    [Fact]
    public void Parses_the_url_an_adcs_ca_writes()
    {
        const string url =
            "ldap:///CN=Contoso Root CA,CN=ROOT01,CN=CDP,CN=Public Key Services,CN=Services,"
            + "CN=Configuration,DC=contoso,DC=com?certificateRevocationList?base?"
            + "objectClass=cRLDistributionPoint";

        LdapCdpUrl.TryParse(url, out var parsed, out var error).Should().BeTrue(error);

        parsed!.IsServerless.Should().BeTrue();
        parsed.Host.Should().BeEmpty();
        parsed.DistinguishedName.Should().StartWith("CN=Contoso Root CA,CN=ROOT01,CN=CDP");
        parsed.Attribute.Should().Be("certificateRevocationList");
        parsed.Scope.Should().Be("base");
        // The filter arrives without its outer parentheses, which is legal in a
        // URL and refused by a directory searcher.
        parsed.Filter.Should().Be("(objectClass=cRLDistributionPoint)");
        parsed.ToDirectoryPath().Should().StartWith("LDAP://CN=Contoso Root CA,");
    }

    [Fact]
    public void Decodes_percent_escapes_in_the_entry_name()
    {
        const string url =
            "ldap:///CN=Contoso%20Root%20CA,CN=CDP,DC=contoso,DC=com?certificateRevocationList";

        LdapCdpUrl.TryParse(url, out var parsed, out _).Should().BeTrue();

        parsed!.DistinguishedName.Should().Be("CN=Contoso Root CA,CN=CDP,DC=contoso,DC=com");
    }

    [Fact]
    public void Keeps_a_named_server_and_port()
    {
        const string url = "ldap://dc01.contoso.com:389/CN=CDP,DC=contoso,DC=com?certificateRevocationList";

        LdapCdpUrl.TryParse(url, out var parsed, out _).Should().BeTrue();

        parsed!.IsServerless.Should().BeFalse();
        parsed.Host.Should().Be("dc01.contoso.com");
        parsed.Port.Should().Be(389);
        parsed.ToDirectoryPath().Should().Be("LDAP://dc01.contoso.com:389/CN=CDP,DC=contoso,DC=com");
    }

    [Fact]
    public void Strips_the_binary_option_off_the_attribute()
    {
        const string url = "ldap:///CN=CDP,DC=contoso,DC=com?certificateRevocationList;binary?base";

        LdapCdpUrl.TryParse(url, out var parsed, out _).Should().BeTrue();

        // The directory hands back bytes either way, and the option would not
        // match a property name in the result.
        parsed!.Attribute.Should().Be("certificateRevocationList");
    }

    [Fact]
    public void Takes_the_first_attribute_when_several_are_named()
    {
        const string url = "ldap:///CN=CDP,DC=contoso,DC=com?deltaRevocationList,certificateRevocationList?base";

        LdapCdpUrl.TryParse(url, out var parsed, out _).Should().BeTrue();

        parsed!.Attribute.Should().Be("deltaRevocationList");
    }

    [Fact]
    public void Defaults_the_attribute_the_scope_and_the_filter()
    {
        LdapCdpUrl.TryParse("ldap:///CN=CDP,DC=contoso,DC=com", out var parsed, out _)
            .Should().BeTrue();

        parsed!.Attribute.Should().Be(LdapCdpUrl.DefaultAttribute);
        parsed.Scope.Should().Be("base");
        parsed.Filter.Should().Be("(objectClass=*)");
    }

    [Fact]
    public void Keeps_a_filter_that_already_carries_its_parentheses()
    {
        const string url = "ldap:///CN=CDP,DC=contoso,DC=com?certificateRevocationList?base?(objectClass=*)";

        LdapCdpUrl.TryParse(url, out var parsed, out _).Should().BeTrue();

        parsed!.Filter.Should().Be("(objectClass=*)");
    }

    [Theory]
    [InlineData("http://pki.contoso.com/root.crl")]
    [InlineData("file://\\\\server\\share\\root.crl")]
    [InlineData("")]
    [InlineData("   ")]
    public void Refuses_anything_that_is_not_an_ldap_url(string url)
    {
        LdapCdpUrl.TryParse(url, out var parsed, out var error).Should().BeFalse();

        parsed.Should().BeNull();
        error.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void Refuses_an_ldap_url_that_names_no_entry()
    {
        LdapCdpUrl.TryParse("ldap:///", out var parsed, out var error).Should().BeFalse();

        parsed.Should().BeNull();
        error.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void Accepts_the_secure_scheme()
    {
        LdapCdpUrl.TryParse("ldaps://dc01.contoso.com/CN=CDP,DC=contoso,DC=com", out var parsed, out _)
            .Should().BeTrue();

        parsed!.Host.Should().Be("dc01.contoso.com");
    }
}

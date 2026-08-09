using Certus.Adcs;

namespace Certus.Core.Tests.ActiveDirectory;

/// <summary>
/// Tests for the pure parts of the real directory lookup: the category to
/// type mapping and the LDAP filter escaping. The DirectorySearcher paths
/// themselves need a domain and get manual verification on the lab CA, the
/// CA discovery precedent; these two statics are where a silent mistake
/// would misclassify or widen a search, so they are pinned here.
/// </summary>
public class AdPrincipalLookupTests
{
    [Theory]
    [InlineData("CN=Person,CN=Schema,CN=Configuration,DC=home,DC=local", "user")]
    [InlineData("CN=Computer,CN=Schema,CN=Configuration,DC=home,DC=local", "computer")]
    [InlineData("CN=Group,CN=Schema,CN=Configuration,DC=home,DC=local", "group")]
    [InlineData("CN=ms-DS-Managed-Service-Account,CN=Schema,CN=Configuration,DC=home,DC=local", "service account")]
    [InlineData("CN=ms-DS-Group-Managed-Service-Account,CN=Schema,CN=Configuration,DC=home,DC=local", "service account")]
    [InlineData("cn=person,CN=Schema,CN=Configuration,DC=home,DC=local", "user")]
    public void TypeFromCategory_MapsTheAdmittedCategories(string categoryDn, string expected)
    {
        AdPrincipalLookup.TypeFromCategory(categoryDn).Should().Be(expected);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("CN=Foreign-Security-Principal,CN=Schema,CN=Configuration,DC=home,DC=local")]
    [InlineData("CN=Contact,CN=Schema,CN=Configuration,DC=home,DC=local")]
    // A category CN that merely starts like an admitted one must not match:
    // the mapping anchors on the trailing comma.
    [InlineData("CN=PersonX,CN=Schema,CN=Configuration,DC=home,DC=local")]
    public void TypeFromCategory_RefusesEverythingElse(string? categoryDn)
    {
        AdPrincipalLookup.TypeFromCategory(categoryDn).Should().BeNull();
    }

    [Fact]
    public void EscapeFilterValue_EscapesTheFilterMetacharacters()
    {
        // RFC 4515: a typed query must never terminate or extend the filter.
        AdPrincipalLookup.EscapeFilterValue(@"a\b*c(d)e" + '\0')
            .Should().Be(@"a\5cb\2ac\28d\29e\00");
    }

    [Fact]
    public void EscapeFilterValue_LeavesOrdinaryNamesAlone()
    {
        AdPrincipalLookup.EscapeFilterValue("Web Admins").Should().Be("Web Admins");
        AdPrincipalLookup.EscapeFilterValue("WEB01$").Should().Be("WEB01$");
    }
}

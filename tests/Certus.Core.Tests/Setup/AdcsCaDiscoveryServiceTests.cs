using System.DirectoryServices;
using Certus.Adcs;

namespace Certus.Core.Tests.Setup;

/// <summary>
/// The searcher the setup wizard's CA discovery runs, issue #466. The read
/// itself needs a domain and is proved on the lab, the same stance as
/// <c>AdPrincipalLookup</c>, but the search it runs is built without one:
/// neither the entry nor the searcher binds until the search is executed, so
/// these run on any Windows box.
///
/// <para>The deadlines are asserted as the relations that make them work rather
/// than as numbers. DirectorySearcher's default for all three is minus one
/// second, which means wait for ever, and that default is what discovery ran
/// with until #466.</para>
/// </summary>
public class AdcsCaDiscoveryServiceTests
{
    private const string EnrollmentServicesPath =
        "LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=test";

    [Fact]
    public void TheSearch_GivesUpOnADomainControllerThatStopsAnswering()
    {
        using var entry = new DirectoryEntry(EnrollmentServicesPath);
        using var searcher = AdcsCaDiscoveryService.CreateSearcher(entry);

        searcher.ClientTimeout.Should().BePositive(
            "without a client timeout a domain controller that stops answering the search holds the thread for the OS level TCP timeout");
        searcher.ClientTimeout.Should().BeLessThanOrEqualTo(TimeSpan.FromMinutes(1),
            "the wizard's CA step waits on this search before it can offer the pick list");

        searcher.ServerTimeLimit.Should().BePositive();
        searcher.ServerTimeLimit.Should().BeLessThan(searcher.ClientTimeout,
            "the server should stop and answer before the client abandons the search, as every other reader has it");

        // PageSize makes this a paged search, and a paged search is bounded
        // page by page as well as overall.
        searcher.PageSize.Should().BePositive();
        searcher.ServerPageTimeLimit.Should().BePositive();
        searcher.ServerPageTimeLimit.Should().BeLessThanOrEqualTo(searcher.ServerTimeLimit);
    }

    [Fact]
    public void TheSearch_IsStillTheEnrollmentServicesSearch()
    {
        // Moving the searcher into a helper must not change what it asks for.
        using var entry = new DirectoryEntry(EnrollmentServicesPath);
        using var searcher = AdcsCaDiscoveryService.CreateSearcher(entry);

        searcher.SearchRoot.Should().BeSameAs(entry);
        searcher.Filter.Should().Be("(objectClass=pKIEnrollmentService)");
        searcher.SearchScope.Should().Be(SearchScope.OneLevel);
        searcher.PageSize.Should().Be(1000);
        searcher.PropertiesToLoad.Cast<string>()
            .Should().BeEquivalentTo(["cn", "dNSHostName", "displayName"]);
    }
}

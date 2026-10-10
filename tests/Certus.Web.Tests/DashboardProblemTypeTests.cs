using System.Reflection;
using Certus.Web.Controllers.Dashboard;

namespace Certus.Web.Tests;

/// <summary>
/// Every problem type the dashboard API emits resolves to a page we publish
/// (issue #402). The pages live on the gh-pages branch of the public
/// haruspexsystems/Ducks-in-a-Row repository, outside this solution, so nothing
/// here can fetch them. What this file pins instead is the list of slugs that
/// branch publishes: a constant
/// added to <see cref="DashboardProblemType"/> without a page, or a slug renamed
/// after a release has shipped it, fails here rather than reaching a reviewer
/// as a 404.
///
/// The integration tests that assert a type on the wire keep the full URI as a
/// literal rather than reading the constant, so a wrong constant fails them too.
/// </summary>
public class DashboardProblemTypeTests
{
    private const string Prefix = "https://ducksinarow.dev/problems/";

    /// <summary>
    /// The slugs with a page under https://ducksinarow.dev/problems/. Adding one
    /// here means publishing its page in the same change; removing one means a
    /// shipped release now points at nothing, so it should not happen.
    /// </summary>
    private static readonly string[] PublishedSlugs =
    [
        "ca-access-denied",
        "ca-error",
        "ca-unavailable",
        "certificate-already-revoked",
        "certificate-not-revocable",
        "certificate-unavailable",
        "invalid-revocation-reason",
        "revocation-blocked-by-guardrail",
        "revocation-out-of-scope",
        "revocation-target-mismatch",
    ];

    private static List<string> DeclaredTypes() =>
        typeof(DashboardProblemType)
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(f => f.IsLiteral && f.FieldType == typeof(string))
            .Select(f => (string)f.GetRawConstantValue()!)
            .ToList();

    [Fact]
    public void EveryType_IsAPublishedPageOnOurDomain()
    {
        var types = DeclaredTypes();

        types.Should().NotBeEmpty(
            "the assertions below prove nothing if the reflection stops finding the "
            + "constants, which a change to how DashboardProblemType declares them would "
            + "do quietly");

        foreach (var type in types)
        {
            type.Should().StartWith(Prefix,
                "a problem type must resolve on a domain Haruspex Systems controls");
            type[Prefix.Length..].Should().MatchRegex("^[a-z]+(-[a-z]+)*$",
                "a slug is lower case words joined by single hyphens, the shape the "
                + "site's file names take");
        }

        // Also catches two constants sharing one URI, which would leave a client
        // unable to tell the two problems apart: the counts would then differ.
        types.Select(t => t[Prefix.Length..]).Should().BeEquivalentTo(PublishedSlugs,
            "each constant needs a page on the site and each page was promised by a "
            + "release, so the two lists move together");
    }
}

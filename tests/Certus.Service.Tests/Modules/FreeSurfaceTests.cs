using System.Globalization;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Certus.Service.Tests.Modules;

/// <summary>
/// The mechanical half of the free product boundary (issue #652, issue #655). Free is one CA; run is
/// free, prove and integrate are paid. A new API route or dashboard area is a new capability, and a
/// capability is paid unless someone decided otherwise, so every route the service host maps and every
/// dashboard area the frontend ships must appear in <c>FreeSurface.md</c> beside this file, each with
/// the date of its free decision and the reason. A pull request that adds one without extending the
/// list fails here, and the merge gate's review lens is the judgment half that reads the reason.
///
/// <para>The routes are read off the real service host's endpoint data source, so a controller, a
/// minimal API map and a fallback all count, whichever way they were registered. The areas are read
/// from the frontend source: every route path in <c>App.tsx</c> and every page, card, section, step
/// or wizard component under <c>src/pages</c>.</para>
/// </summary>
public class FreeSurfaceTests
{
    private const string ListFile = "tests/Certus.Service.Tests/Modules/FreeSurface.md";

    /// <summary>One row of the committed list.</summary>
    private sealed record Entry(string Kind, string Surface, string Decided, string Decision, int Line);

    [Fact]
    public void EveryApiRouteHasADatedFreeDecision()
    {
        var live = ApiRoutes();

        // Anti vacuity: the inventory sees the ACME directory, the licence API and the health check.
        live.Should().HaveCountGreaterThan(40);
        live.Should().Contain(s => s.EndsWith(" /acme/{template}/directory", StringComparison.Ordinal));
        live.Should().Contain(s => s.Contains("/api/settings/licence", StringComparison.Ordinal));
        live.Should().Contain("ANY /health");

        AssertListed("api", live);
    }

    [Fact]
    public void EveryDashboardAreaHasADatedFreeDecision()
    {
        var live = DashboardAreas();

        live.Should().Contain("route /settings");
        live.Should().Contain("component pages/settings/LicenceCard.tsx");
        live.Should().HaveCountGreaterThan(20);

        AssertListed("area", live);
    }

    [Fact]
    public void EveryEntryCarriesADateAndAFreeDecision()
    {
        var entries = ReadList();
        entries.Should().HaveCountGreaterThan(60, "the list was read");

        var problems = new List<string>();
        var today = DateOnly.FromDateTime(DateTime.UtcNow);
        foreach (var e in entries)
        {
            if (e.Kind is not ("api" or "area"))
                problems.Add($"line {e.Line}: kind '{e.Kind}' is neither api nor area");
            if (!DateOnly.TryParseExact(e.Decided, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var date))
                problems.Add($"line {e.Line}: '{e.Decided}' is not a yyyy-MM-dd date");
            else if (date > today)
                problems.Add($"line {e.Line}: {e.Decided} is in the future");
            // A decision says free and why, citing the boundary row it rests on.
            if (!e.Decision.StartsWith("free: ", StringComparison.Ordinal) || e.Decision.Length < 12)
                problems.Add($"line {e.Line}: the decision must read 'free: <reason>', got '{e.Decision}'");
        }

        var duplicates = entries.GroupBy(e => (e.Kind, e.Surface)).Where(g => g.Count() > 1).Select(g => $"{g.Key.Kind} {g.Key.Surface}");
        problems.AddRange(duplicates.Select(d => $"listed twice: {d}"));

        problems.Should().BeEmpty();
    }

    private static void AssertListed(string kind, IReadOnlyCollection<string> live)
    {
        var listed = ReadList().Where(e => e.Kind == kind).Select(e => e.Surface).ToHashSet(StringComparer.Ordinal);

        var unlisted = live.Where(s => !listed.Contains(s)).Order(StringComparer.Ordinal).ToList();
        var stale = listed.Where(s => !live.Contains(s)).Order(StringComparer.Ordinal).ToList();

        // The rows are written out ready to paste, with today's date, so the decision is all that is
        // left to write; and writing it is the point.
        var today = DateTime.UtcNow.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        unlisted.Should().BeEmpty(
            $"every {kind} needs a dated free decision in {ListFile}, or belongs in the paid module. Add:{Environment.NewLine}" +
            string.Join(Environment.NewLine, unlisted.Select(s => $"| {kind} | `{s}` | {today} | free: <the boundary row this rests on> |")));
        stale.Should().BeEmpty($"{ListFile} lists a {kind} the product no longer has; remove the row");
    }

    private static List<Entry> ReadList()
    {
        var path = Path.Combine(RepoRoot(), ListFile);
        var lines = File.ReadAllLines(path);
        var rows = new List<Entry>();
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i].Trim();
            if (!line.StartsWith('|') || line.StartsWith("| kind", StringComparison.Ordinal) || line.StartsWith("|--", StringComparison.Ordinal) || line.StartsWith("| ---", StringComparison.Ordinal))
                continue;
            var cells = line.Trim('|').Split('|').Select(c => c.Trim()).ToArray();
            cells.Should().HaveCount(4, $"{ListFile} line {i + 1} has four columns: kind, surface, decided, decision");
            rows.Add(new Entry(cells[0], cells[1].Trim('`'), cells[2], cells[3], i + 1));
        }
        return rows;
    }

    /// <summary>Every endpoint the real service host maps, as "VERB /pattern".</summary>
    private static HashSet<string> ApiRoutes()
    {
        using var factory = new ServiceHostFactory();
        _ = factory.Server;
        var source = factory.Services.GetRequiredService<EndpointDataSource>();

        var routes = new HashSet<string>(StringComparer.Ordinal);
        foreach (var endpoint in source.Endpoints.OfType<RouteEndpoint>())
        {
            var pattern = "/" + (endpoint.RoutePattern.RawText ?? string.Empty).TrimStart('/');
            var methods = endpoint.Metadata.GetMetadata<IHttpMethodMetadata>()?.HttpMethods;
            if (methods is null || methods.Count == 0)
                routes.Add($"ANY {pattern}");
            else
                foreach (var method in methods)
                    routes.Add($"{method} {pattern}");
        }
        return routes;
    }

    /// <summary>Every dashboard route path and every page level component.</summary>
    private static HashSet<string> DashboardAreas()
    {
        var src = Path.Combine(RepoRoot(), "src", "frontend", "src");
        var areas = new HashSet<string>(StringComparer.Ordinal);

        var app = File.ReadAllText(Path.Combine(src, "App.tsx"));
        foreach (Match m in Regex.Matches(app, "<Route\\s+path=\"(?<p>[^\"]+)\""))
            areas.Add($"route {m.Groups["p"].Value}");

        var pages = Path.Combine(src, "pages");
        foreach (var file in Directory.EnumerateFiles(pages, "*.tsx", SearchOption.AllDirectories))
        {
            var name = Path.GetFileNameWithoutExtension(file);
            if (Regex.IsMatch(name, "(Page|Card|Section|Step|Wizard)$"))
                areas.Add("component " + Path.GetRelativePath(src, file).Replace('\\', '/'));
        }
        return areas;
    }

    private static string RepoRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Certus.sln")))
            directory = directory.Parent;
        return directory?.FullName
            ?? throw new InvalidOperationException($"Could not find Certus.sln walking up from {AppContext.BaseDirectory}.");
    }
}

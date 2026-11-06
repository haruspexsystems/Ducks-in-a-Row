using System.Text.RegularExpressions;

namespace Certus.Core.Tests.ActiveDirectory;

/// <summary>
/// Pins the project rule that every <c>DirectorySearcher</c> sets
/// <c>ClientTimeout</c> and <c>ServerTimeLimit</c>, and that a paged one also
/// sets <c>ServerPageTimeLimit</c>. Without them a domain controller that stops
/// answering holds a thread pool thread for the OS level TCP timeout. CA
/// discovery ran without either until issue #466, while every other reader
/// carried both, and nothing noticed because a directory read cannot be run
/// here: the readers need a domain and are proved on the lab.
///
/// <para><b>What it scans.</b> Every C# file under <c>src/</c> and <c>tools/</c>,
/// skipping build output. <c>tools/AdcsQiProbe</c> is outside Certus.sln, so a
/// scan of the text is the only test that reaches it.</para>
///
/// <para><b>The shape it accepts.</b> Each construction must carry an object
/// initializer that names the deadlines, which is how every reader in the tree
/// writes it today. A searcher whose limits are assigned on later lines is
/// reported rather than followed: one shape that a scan can read is worth more
/// than a scan that tries to follow every shape and misses one. Comments and
/// literals are blanked before the scan, so a commented out deadline does not
/// count as set and a construction named in prose is not reported.</para>
/// </summary>
public class DirectorySearcherDeadlinesTests
{
    private static readonly string[] ScannedRoots = ["src", "tools"];
    private static readonly HashSet<string> SkippedDirectories =
        new(StringComparer.OrdinalIgnoreCase) { "bin", "obj", "node_modules" };

    // Both ways to write the construction: the type named after new, and the
    // target typed new whose type is named on the left.
    private static readonly Regex Construction = new(
        @"\bnew\s+(?:System\.DirectoryServices\.)?DirectorySearcher\b" +
        @"|\bDirectorySearcher\s+\w+\s*=\s*new\b(?=\s*\()",
        RegexOptions.CultureInvariant);

    private static readonly Regex ClientTimeout = new(@"\bClientTimeout\s*=(?!=)", RegexOptions.CultureInvariant);
    private static readonly Regex ServerTimeLimit = new(@"\bServerTimeLimit\s*=(?!=)", RegexOptions.CultureInvariant);
    private static readonly Regex ServerPageTimeLimit = new(@"\bServerPageTimeLimit\s*=(?!=)", RegexOptions.CultureInvariant);
    private static readonly Regex PageSize = new(@"\bPageSize\s*=(?!=)", RegexOptions.CultureInvariant);

    [Fact]
    public void EveryDirectorySearcher_SetsItsDeadlines()
    {
        var root = RepositoryRoot();
        var found = new List<string>();
        var faults = new List<string>();

        foreach (var scanned in ScannedRoots)
        {
            foreach (var file in SourceFiles(Path.Combine(root, scanned)))
            {
                var relative = Path.GetRelativePath(root, file).Replace('\\', '/');
                foreach (var (line, fault) in Inspect(File.ReadAllText(file)))
                {
                    found.Add($"{relative}:{line}");
                    if (fault is not null)
                        faults.Add($"{relative}:{line}  {fault}");
                }
            }
        }

        // Anti vacuity: the scan found the readers, including the one #466 fixed.
        found.Should().HaveCountGreaterThan(3, "a scan that finds almost nothing proves nothing");
        found.Should().Contain(f => f.StartsWith("src/Certus.Adcs/AdcsCaDiscoveryService.cs:", StringComparison.Ordinal));
        found.Should().Contain(f => f.StartsWith("src/Certus.Adcs/AdcsTemplateDirectoryLookup.cs:", StringComparison.Ordinal));

        faults.Should().BeEmpty(
            "every DirectorySearcher sets ClientTimeout and ServerTimeLimit (and ServerPageTimeLimit when it pages), " +
            "or a domain controller that stops answering holds the thread for the OS level TCP timeout");
    }

    [Theory]
    [InlineData("using var s = new DirectorySearcher(entry) { Filter = f };", "ClientTimeout")]
    [InlineData("using var s = new DirectorySearcher(entry) { ClientTimeout = a };", "ServerTimeLimit")]
    [InlineData("using var s = new DirectorySearcher(entry) { ServerTimeLimit = b, ServerPageTimeLimit = b };", "ClientTimeout")]
    [InlineData("using var s = new DirectorySearcher(entry) { ClientTimeout = a, ServerTimeLimit = b, PageSize = 1000 };", "ServerPageTimeLimit")]
    [InlineData("var s = new DirectorySearcher(entry);\ns.ClientTimeout = a;\ns.ServerTimeLimit = b;", "object initializer")]
    [InlineData("DirectorySearcher s = new(entry) { Filter = f };", "ClientTimeout")]
    [InlineData("var s = new System.DirectoryServices.DirectorySearcher { Filter = f };", "ClientTimeout")]
    public void TheScan_ReportsASearcherWithoutItsDeadlines(string source, string expected)
    {
        Inspect(source).Should().ContainSingle()
            .Which.Fault.Should().NotBeNull().And.Contain(expected);
    }

    [Theory]
    [InlineData("using var s = new DirectorySearcher(entry) { ClientTimeout = a, ServerTimeLimit = b };")]
    [InlineData("using var s = new DirectorySearcher(entry)\n{\n    PageSize = 1000,\n    ClientTimeout = a,\n    ServerTimeLimit = b,\n    ServerPageTimeLimit = b\n};")]
    // Nested parentheses in the arguments, and braces from an interpolated
    // filter inside the initializer, must not end either span early.
    [InlineData("using (var s = new DirectorySearcher(new DirectoryEntry(Path(x)), \"(&(a=b)(c=d))\")\n{\n    Filter = $\"(cn={Escape(n)})\",\n    ClientTimeout = a,\n    ServerTimeLimit = b,\n})\n{\n}")]
    [InlineData("DirectorySearcher s = new(entry) { ClientTimeout = a, ServerTimeLimit = b };")]
    public void TheScan_AcceptsASearcherWithItsDeadlines(string source)
    {
        Inspect(source).Should().ContainSingle().Which.Fault.Should().BeNull();
    }

    [Fact]
    public void TheScan_IgnoresTheTypeNamedWithoutAConstruction()
    {
        Inspect("/// <see cref=\"DirectorySearcher\"/>\nprivate static DirectorySearcher Build(DirectoryEntry e) => null!;")
            .Should().BeEmpty();
    }

    [Theory]
    [InlineData("// replaced new DirectorySearcher(entry) with CreateSearcher")]
    [InlineData("/* new DirectorySearcher(entry) */")]
    [InlineData("var hint = \"call new DirectorySearcher(entry) here\";")]
    [InlineData("var hint = @\"call new DirectorySearcher(entry) \"\"here\"\"\";")]
    public void TheScan_IgnoresAConstructionInACommentOrALiteral(string source)
    {
        Inspect(source).Should().BeEmpty();
    }

    [Fact]
    public void TheScan_DoesNotCountACommentedOutDeadline()
    {
        Inspect("using var s = new DirectorySearcher(entry)\n{\n    // ClientTimeout = a,\n    ServerTimeLimit = b\n};")
            .Should().ContainSingle().Which.Fault.Should().Contain("ClientTimeout");
    }

    [Fact]
    public void TheScan_IsNotMisledByABraceInsideAFilter()
    {
        // An escaped brace in an interpolated filter would otherwise leave the
        // first span open to the end of the text, and the second searcher's
        // deadlines would pass for the first one's.
        var results = Inspect(
            "using var s = new DirectorySearcher(entry) { Filter = $\"(cn={{x)\", ServerTimeLimit = b };\n" +
            "using var t = new DirectorySearcher(other) { Filter = \"(cn=})\", ClientTimeout = a, ServerTimeLimit = b };");

        results.Should().HaveCount(2);
        results[0].Should().Be((1, "does not set ClientTimeout"));
        results[1].Should().Be((2, (string?)null));
    }

    [Fact]
    public void Blank_KeepsLineBreaksAndCode()
    {
        var source = "a = \"x\\\"y\"; // note\nb = '\\'' + @\"p\"\"q\"; /* c\nd */ e = \"\"\"r\"s\"\"\";";
        var blanked = Blank(source);

        // Same length, so every index and line number still holds.
        blanked.Should().HaveLength(source.Length);
        blanked.Split('\n').Select(l => Regex.Replace(l, @"\s+", " ").Trim())
            .Should().Equal("a = ;", "b = + @ ;", "e = ;");
    }

    /// <summary>
    /// Every construction in <paramref name="source"/>, with its one based line
    /// and the deadline it is missing, or a null fault when it sets them all.
    /// </summary>
    internal static IReadOnlyList<(int Line, string? Fault)> Inspect(string original)
    {
        // Comments and literals are blanked first, so a commented out deadline
        // does not count as set, a construction named in prose is not one, and
        // a brace or parenthesis inside a filter string cannot move a span end.
        var source = Blank(original);
        var results = new List<(int, string?)>();
        foreach (Match match in Construction.Matches(source))
        {
            var line = 1 + source.AsSpan(0, match.Index).Count('\n');
            var position = SkipWhitespace(source, match.Index + match.Length);

            if (position < source.Length && source[position] == '(')
                position = SkipWhitespace(source, SkipBalanced(source, position, '(', ')'));

            if (position >= source.Length || source[position] != '{')
            {
                results.Add((line, "is built without an object initializer; set ClientTimeout and ServerTimeLimit in one"));
                continue;
            }

            var end = SkipBalanced(source, position, '{', '}');
            var initializer = source[position..end];

            var missing = new List<string>();
            if (!ClientTimeout.IsMatch(initializer)) missing.Add("ClientTimeout");
            if (!ServerTimeLimit.IsMatch(initializer)) missing.Add("ServerTimeLimit");
            if (PageSize.IsMatch(initializer) && !ServerPageTimeLimit.IsMatch(initializer))
                missing.Add("ServerPageTimeLimit (the search is paged)");

            results.Add((line, missing.Count == 0 ? null : "does not set " + string.Join(", ", missing)));
        }
        return results;
    }

    /// <summary>
    /// The text with every comment and every string or character literal
    /// replaced by spaces, line breaks kept so line numbers still hold. It
    /// knows the literal forms this tree writes (regular, verbatim, raw, and
    /// their interpolated spellings, whose holes are blanked with them) and no
    /// more: it is a scanner for one rule, not a C# lexer.
    /// </summary>
    internal static string Blank(string source)
    {
        var text = source.ToCharArray();
        var i = 0;
        while (i < text.Length)
        {
            var next = i + 1 < text.Length ? text[i + 1] : '\0';
            int stop;
            if (text[i] == '/' && next == '/')
            {
                stop = source.IndexOf('\n', i);
                stop = stop < 0 ? text.Length : stop;
            }
            else if (text[i] == '/' && next == '*')
            {
                stop = source.IndexOf("*/", i + 2, StringComparison.Ordinal);
                stop = stop < 0 ? text.Length : stop + 2;
            }
            else if (text[i] == '"' || text[i] == '\'')
            {
                stop = LiteralEnd(source, i);
            }
            else
            {
                i++;
                continue;
            }

            for (var j = i; j < stop; j++)
            {
                if (text[j] != '\n')
                    text[j] = ' ';
            }
            i = stop;
        }
        return new string(text);
    }

    /// <summary>The index just past the literal whose opening quote is at <paramref name="start"/>.</summary>
    private static int LiteralEnd(string source, int start)
    {
        var quote = source[start];
        if (quote == '"')
        {
            var run = 0;
            while (start + run < source.Length && source[start + run] == '"')
                run++;
            if (run >= 3)
            {
                // A raw string literal closes on the same number of quotes.
                var close = source.IndexOf(new string('"', run), start + run, StringComparison.Ordinal);
                return close < 0 ? source.Length : close + run;
            }
        }

        var verbatim = quote == '"' && IsVerbatimPrefix(source, start);
        for (var i = start + 1; i < source.Length; i++)
        {
            var c = source[i];
            if (verbatim)
            {
                if (c != '"') continue;
                if (i + 1 < source.Length && source[i + 1] == '"') { i++; continue; }
                return i + 1;
            }
            if (c == '\\') { i++; continue; }
            if (c == quote) return i + 1;
            if (c == '\n') return i;
        }
        return source.Length;
    }

    private static bool IsVerbatimPrefix(string source, int quote)
    {
        for (var i = quote - 1; i >= 0 && i >= quote - 2; i--)
        {
            if (source[i] == '@') return true;
            if (source[i] != '$') return false;
        }
        return false;
    }

    private static int SkipWhitespace(string source, int position)
    {
        while (position < source.Length && char.IsWhiteSpace(source[position]))
            position++;
        return position;
    }

    /// <summary>
    /// The index just past the bracket that closes the one at
    /// <paramref name="open"/>, or the end of the text when it never closes.
    /// It runs over <see cref="Blank"/>'s output, so no literal is counted.
    /// </summary>
    private static int SkipBalanced(string source, int open, char opening, char closing)
    {
        var depth = 0;
        for (var i = open; i < source.Length; i++)
        {
            if (source[i] == opening) depth++;
            else if (source[i] == closing && --depth == 0) return i + 1;
        }
        return source.Length;
    }

    private static IEnumerable<string> SourceFiles(string directory)
    {
        foreach (var file in Directory.EnumerateFiles(directory, "*.cs"))
            yield return file;

        foreach (var child in Directory.EnumerateDirectories(directory))
        {
            if (SkippedDirectories.Contains(Path.GetFileName(child)))
                continue;
            foreach (var file in SourceFiles(child))
                yield return file;
        }
    }

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Certus.sln")))
            directory = directory.Parent;
        return directory?.FullName
            ?? throw new InvalidOperationException($"Could not find Certus.sln walking up from {AppContext.BaseDirectory}.");
    }
}

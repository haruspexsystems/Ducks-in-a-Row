using System.DirectoryServices;
using Certus.Core.Crl;

namespace Certus.Adcs.Crl;

/// <summary>
/// Reads a CRL from an LDAP distribution point.
///
/// This is the distribution point that answers on a domain joined network, and
/// on most estates it is the one holding the offline root's CRL, because
/// publishing a root CRL to the directory with <c>certutil -dspublish</c> is
/// the documented half of the renewal ceremony.
///
/// It is a plain directory read, so the rules in the directory lookups section
/// of CLAUDE.md apply rather than the ADCS COM ones: best effort, never an
/// exception to the caller, and both timeouts always set, because a black holed
/// domain controller would otherwise hold a thread for the operating system's
/// own TCP timeout.
///
/// The bind stays serverless when the URL is, which every ADCS written CDP URL
/// is. Naming a domain controller would pin the read to one server and lose the
/// locator.
///
/// Like AdPrincipalLookup and AdcsCaDiscoveryService, it needs a live domain to
/// answer, so it is proved on a lab rather than by unit tests: the URL parsing
/// and the CRL reading it hands off to are unit tested on their own, and
/// tools/AdcsQiProbe links this file so a lab run exercises this exact code
/// against a real directory. Keep it free of any dependency beyond
/// System.DirectoryServices, or that link stops compiling.
/// </summary>
public static class LdapCrlFetcher
{
    /// <summary>
    /// Reads every value of the attribute the URL names from the entry the URL
    /// names. The entry can hold more than one CRL, one per CA key, so all the
    /// values come back and the caller matches them to the key it watches.
    /// </summary>
    public static CrlFetchResult Fetch(
        LdapCdpUrl url,
        TimeSpan clientTimeout,
        TimeSpan serverTimeLimit)
    {
        ArgumentNullException.ThrowIfNull(url);

        try
        {
            using var entry = new DirectoryEntry(url.ToDirectoryPath());
            using var searcher = new DirectorySearcher(entry)
            {
                // A CDP URL names one entry. Base scope is what the URL asks for
                // and what keeps this from walking a directory.
                SearchScope = SearchScope.Base,
                Filter = url.Filter,
                SizeLimit = 1,
                ClientTimeout = clientTimeout,
                ServerTimeLimit = serverTimeLimit,
            };
            searcher.PropertiesToLoad.Add(url.Attribute);

            var found = searcher.FindOne();
            if (found is null)
                return CrlFetchResult.Failure("The directory entry was not found.");

            var crls = ReadValues(found, url.Attribute);
            if (crls.Count == 0)
            {
                return CrlFetchResult.Failure(
                    $"The directory entry holds no {url.Attribute} value.");
            }

            return CrlFetchResult.Success(crls);
        }
        catch (Exception ex)
        {
            // Broad on purpose, matching AdPrincipalLookup and
            // AdcsCaDiscoveryService: a directory read is best effort and never
            // throws at its caller. The failures arrive in several shapes, from
            // a COMException for no such object or a server that is down to an
            // ArgumentException for a path the URL mangled, and every one of
            // them means the same thing here, which is that this distribution
            // point did not answer.
            return CrlFetchResult.Failure(ex.Message);
        }
    }

    /// <summary>
    /// Pulls the byte values out of a search result. The property collection
    /// keys are lower cased by the searcher, so the attribute is matched
    /// without regard to case rather than indexed directly.
    /// </summary>
    private static List<byte[]> ReadValues(SearchResult result, string attribute)
    {
        var values = new List<byte[]>();

        foreach (string name in result.Properties.PropertyNames)
        {
            if (!string.Equals(name, attribute, StringComparison.OrdinalIgnoreCase))
                continue;

            foreach (var value in result.Properties[name])
            {
                if (value is byte[] bytes && bytes.Length > 0)
                    values.Add(bytes);
            }
        }

        return values;
    }
}

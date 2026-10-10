using System.DirectoryServices;
using Microsoft.Extensions.Logging;

namespace Certus.Adcs;

/// <summary>
/// Resolves ADCS certificate template display names from Active Directory.
///
/// CR_PROP_TEMPLATES (read by AdcsClient.GetTemplatesAsync) returns the
/// template programmatic name (the AD <c>cn</c> attribute, no spaces). The
/// human readable name that administrators see in certsrv.msc and that ACME
/// clients are typically configured with comes from the <c>displayName</c>
/// attribute on the same AD object. ADCS exposes that attribute through the
/// Configuration partition under
/// <c>CN=Certificate Templates,CN=Public Key Services,CN=Services,&lt;ConfigurationNamingContext&gt;</c>.
///
/// This lookup is best effort. If the host is not domain joined, the service
/// account cannot read the Configuration partition, or AD is unreachable, the
/// caller falls back to using the programmatic name as the display name.
/// Issue #17 motivates the lookup — without it, ACME URLs that use the
/// display name (e.g. <c>/acme/Web%20Server%20ACME/directory</c>) cannot
/// resolve to a template and the directory endpoint returns 404.
/// </summary>
internal static class AdcsTemplateDirectoryLookup
{
    /// <summary>
    /// The attributes read from each <c>pKICertificateTemplate</c> object that are
    /// relevant to the setup wizard: the human readable display name, the Extended
    /// Key Usage OIDs (used to decide which templates can issue server
    /// authentication certificates), and the raw ACME viability attributes the
    /// wizard's template checklist interprets (issuance requirements, subject
    /// source, key algorithm and size).
    /// </summary>
    /// <param name="DisplayName">The AD <c>displayName</c>, or null when absent.</param>
    /// <param name="Ekus">
    /// The OIDs from the multi valued <c>pKIExtendedKeyUsage</c> attribute. Empty
    /// when the template carries no EKU restriction.
    /// </param>
    /// <param name="EnrollmentFlags">Raw <c>msPKI-Enrollment-Flag</c>, or null when absent.</param>
    /// <param name="RaSignatureCount">Raw <c>msPKI-RA-Signature</c>, or null when absent.</param>
    /// <param name="CertificateNameFlags">Raw <c>msPKI-Certificate-Name-Flag</c>, or null when absent.</param>
    /// <param name="MinimalKeySize">Raw <c>msPKI-Minimal-Key-Size</c>, or null when absent.</param>
    /// <param name="SchemaVersion">
    /// Raw <c>msPKI-Template-Schema-Version</c>, or null when absent. Absent is
    /// the normal shape of a version 1 template rather than a failed read: the
    /// whole <c>msPKI-</c> attribute set postdates that schema.
    /// </param>
    /// <param name="PrivateKeyFlags">Raw <c>msPKI-Private-Key-Flag</c>, or null when absent.</param>
    /// <param name="RaApplicationPolicies">
    /// Raw <c>msPKI-RA-Application-Policies</c> values. On the schemas that use
    /// the CNG syntax this carries the key algorithm; on the others it is a list
    /// of registration authority OIDs and carries nothing we want. Handed across
    /// unparsed so the interpretation stays in Certus.Core where it can be unit
    /// tested: see <see cref="Certus.Core.Adcs.RaApplicationPolicies"/>.
    /// </param>
    /// <param name="DefaultCsps">The legacy <c>pKIDefaultCSPs</c> provider list. Empty when absent.</param>
    internal sealed record TemplateAdInfo(
        string? DisplayName,
        IReadOnlyList<string> Ekus,
        int? EnrollmentFlags = null,
        int? RaSignatureCount = null,
        int? CertificateNameFlags = null,
        int? MinimalKeySize = null,
        int? SchemaVersion = null,
        int? PrivateKeyFlags = null,
        IReadOnlyList<string>? RaApplicationPolicies = null,
        IReadOnlyList<string>? DefaultCsps = null);

    /// <summary>
    /// Deadlines for the template search, so a domain controller that stops
    /// answering cannot pin a thread pool thread for the OS level TCP timeout.
    /// The same pair <see cref="AdPrincipalLookup"/> carries, and required by
    /// the project notes for every <see cref="DirectorySearcher"/>. This search
    /// runs behind a five minute cache rather than per keystroke, so it can
    /// afford to be more patient than the principal picker.
    /// </summary>
    private static readonly TimeSpan SearchClientTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan SearchServerTimeLimit = TimeSpan.FromSeconds(20);

    /// <summary>
    /// Returns a case insensitive dictionary mapping each programmatic name (the
    /// AD <c>cn</c>) to its <see cref="TemplateAdInfo"/>. The lookup is best
    /// effort: if the host is not domain joined, the service account cannot read
    /// the Configuration partition, or AD is unreachable, an empty dictionary is
    /// returned and the caller treats every template as unresolved (display name
    /// falls back to the programmatic name, and EKU is left null / "unverified").
    /// </summary>
    public static IDictionary<string, TemplateAdInfo> ResolveTemplates(ILogger logger)
    {
        var result = new Dictionary<string, TemplateAdInfo>(StringComparer.OrdinalIgnoreCase);

        try
        {
            using var rootDse = new DirectoryEntry("LDAP://RootDSE");
            var configContext = rootDse.Properties["configurationNamingContext"]?.Value as string;
            if (string.IsNullOrEmpty(configContext))
            {
                logger.LogWarning(
                    "AD lookup: configurationNamingContext not available; template display names and EKUs cannot be resolved.");
                return result;
            }

            var path = $"LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,{configContext}";
            using var templatesEntry = new DirectoryEntry(path);
            using var searcher = new DirectorySearcher(templatesEntry)
            {
                Filter = "(objectClass=pKICertificateTemplate)",
                SearchScope = SearchScope.OneLevel,
                PageSize = 1000,
                ClientTimeout = SearchClientTimeout,
                ServerTimeLimit = SearchServerTimeLimit,
                ServerPageTimeLimit = SearchServerTimeLimit
            };
            searcher.PropertiesToLoad.Add("cn");
            searcher.PropertiesToLoad.Add("displayName");
            searcher.PropertiesToLoad.Add("pKIExtendedKeyUsage");
            searcher.PropertiesToLoad.Add("msPKI-Enrollment-Flag");
            searcher.PropertiesToLoad.Add("msPKI-RA-Signature");
            searcher.PropertiesToLoad.Add("msPKI-Certificate-Name-Flag");
            searcher.PropertiesToLoad.Add("msPKI-Minimal-Key-Size");
            searcher.PropertiesToLoad.Add("msPKI-Template-Schema-Version");
            searcher.PropertiesToLoad.Add("msPKI-Private-Key-Flag");
            searcher.PropertiesToLoad.Add("msPKI-RA-Application-Policies");
            searcher.PropertiesToLoad.Add("pKIDefaultCSPs");

            using var found = searcher.FindAll();
            foreach (SearchResult sr in found)
            {
                var cn = GetSingle(sr, "cn");
                if (string.IsNullOrWhiteSpace(cn))
                    continue;

                var dn = GetSingle(sr, "displayName");
                var ekus = GetMulti(sr, "pKIExtendedKeyUsage");
                result[cn] = new TemplateAdInfo(
                    dn,
                    ekus,
                    EnrollmentFlags: GetInt(sr, "msPKI-Enrollment-Flag"),
                    RaSignatureCount: GetInt(sr, "msPKI-RA-Signature"),
                    CertificateNameFlags: GetInt(sr, "msPKI-Certificate-Name-Flag"),
                    MinimalKeySize: GetInt(sr, "msPKI-Minimal-Key-Size"),
                    SchemaVersion: GetInt(sr, "msPKI-Template-Schema-Version"),
                    PrivateKeyFlags: GetInt(sr, "msPKI-Private-Key-Flag"),
                    RaApplicationPolicies: GetMulti(sr, "msPKI-RA-Application-Policies"),
                    DefaultCsps: GetMulti(sr, "pKIDefaultCSPs"));
            }

            logger.LogDebug("AD lookup: resolved {Count} certificate templates.", result.Count);
        }
        catch (Exception ex)
        {
            logger.LogWarning(
                ex,
                "AD lookup for certificate templates failed; ACME URLs that use the display name will not resolve and " +
                "the setup wizard cannot verify Extended Key Usage. Either grant the service account read access to the " +
                "AD Configuration partition, or configure ACME clients with the programmatic template name (no spaces).");
        }

        return result;
    }

    private static string? GetSingle(SearchResult sr, string property)
    {
        var values = sr.Properties[property];
        if (values == null || values.Count == 0)
            return null;
        return values[0]?.ToString();
    }

    /// <summary>
    /// Read a single valued integer attribute. AD flag attributes marshal as
    /// <see cref="int"/>, but going through the string form tolerates any
    /// variant the provider hands back. Null means absent or unparsable,
    /// which callers surface as "could not verify".
    /// </summary>
    private static int? GetInt(SearchResult sr, string property)
    {
        var raw = GetSingle(sr, property);
        return int.TryParse(raw, out var value) ? value : null;
    }

    private static IReadOnlyList<string> GetMulti(SearchResult sr, string property)
    {
        var values = sr.Properties[property];
        if (values == null || values.Count == 0)
            return Array.Empty<string>();

        var list = new List<string>(values.Count);
        foreach (var value in values)
        {
            var s = value?.ToString();
            if (!string.IsNullOrWhiteSpace(s))
                list.Add(s.Trim());
        }
        return list;
    }
}

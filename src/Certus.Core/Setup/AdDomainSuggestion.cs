using System.Net.NetworkInformation;
using Certus.Core.Acme.Services;

namespace Certus.Core.Setup;

/// <summary>
/// The machine's Active Directory DNS domain, used to prefill the allowed
/// domain list in the setup wizard and to back the "Add my AD domain" button
/// on the settings page. Same source as <see cref="ServerUrlSuggestion"/>:
/// the primary DNS domain from the machine's IP configuration, which is the
/// AD domain on a domain joined server and empty in a workgroup.
///
/// A suggestion, not a decision: it is inserted as an ordinary editable
/// entry and is never consulted at issuance time.
/// </summary>
public static class AdDomainSuggestion
{
    /// <summary>The domain suggestion, or null when the machine is not domain joined.</summary>
    public static string? Get()
    {
        return Normalize(IPGlobalProperties.GetIPGlobalProperties().DomainName);
    }

    /// <summary>
    /// Pure core of <see cref="Get"/>. Normalizes to the same canonical form
    /// as stored entries (lowercase punycode A labels), so the suggestion
    /// matches the saved list and the add button dedupes correctly for IDN
    /// domains. Null when the machine has no domain or the reported name is
    /// not a usable domain.
    /// </summary>
    internal static string? Normalize(string domainName)
    {
        var domain = domainName.Trim();
        if (domain.Length == 0)
            return null;

        return AllowedDomainsPolicy.TryNormalizeDomain(domain, out var normalized)
            ? normalized
            : null;
    }
}

namespace Certus.Core.Crl;

/// <summary>
/// An LDAP distribution point URL, parsed per RFC 4516.
///
/// A Windows CA writes one of these into every certificate it issues, and an
/// offline root's CRL is normally published to the directory as well, so this
/// is the distribution point that usually answers on a domain joined network.
/// The URL an enterprise CA emits is serverless and looks like
/// <c>ldap:///CN=Example Root,CN=ROOT01,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=example,DC=com?certificateRevocationList?base?objectClass=cRLDistributionPoint</c>,
/// with literal spaces rather than percent escapes, which is why this is parsed
/// by hand rather than through <see cref="Uri"/>.
/// </summary>
/// <param name="Host">The server, empty for the serverless form that binds to the domain.</param>
/// <param name="Port">The port, when the URL names one.</param>
/// <param name="DistinguishedName">The entry holding the CRL, percent decoded.</param>
/// <param name="Attribute">
/// The attribute to read, without its options: <c>certificateRevocationList</c>
/// for a base CRL and <c>deltaRevocationList</c> for a delta. A
/// <c>;binary</c> option is stripped, because System.DirectoryServices returns
/// the value as bytes either way.
/// </param>
/// <param name="Scope">base, one or sub. A CDP URL always names one entry, so base.</param>
/// <param name="Filter">An RFC 4515 filter, parenthesised.</param>
public sealed record LdapCdpUrl(
    string Host,
    int? Port,
    string DistinguishedName,
    string Attribute,
    string Scope,
    string Filter)
{
    /// <summary>The attribute an LDAP CDP URL means when it names none.</summary>
    public const string DefaultAttribute = "certificateRevocationList";

    /// <summary>The attribute a delta CRL is published to.</summary>
    public const string DeltaAttribute = "deltaRevocationList";

    /// <summary>
    /// No host at all, so the bind goes to the domain the host belongs to. This
    /// is the form every ADCS CDP URL uses.
    /// </summary>
    public bool IsServerless => string.IsNullOrEmpty(Host);

    /// <summary>
    /// The ADSI path to bind. Serverless stays serverless: naming a domain
    /// controller here would pin the read to one server and lose the locator.
    /// </summary>
    public string ToDirectoryPath() =>
        IsServerless
            ? $"LDAP://{DistinguishedName}"
            : Port is null
                ? $"LDAP://{Host}/{DistinguishedName}"
                : $"LDAP://{Host}:{Port}/{DistinguishedName}";

    /// <summary>
    /// Parses an <c>ldap://</c> or <c>ldaps://</c> URL. Returns false with a
    /// reason for anything else, including an http URL: the caller decides which
    /// fetcher a distribution point needs by asking this first.
    /// </summary>
    public static bool TryParse(string url, out LdapCdpUrl? parsed, out string? error)
    {
        parsed = null;
        error = null;

        if (string.IsNullOrWhiteSpace(url))
        {
            error = "The distribution point URL was empty.";
            return false;
        }

        var trimmed = url.Trim();
        const string ldapScheme = "ldap://";
        const string ldapsScheme = "ldaps://";

        string remainder;
        if (trimmed.StartsWith(ldapScheme, StringComparison.OrdinalIgnoreCase))
            remainder = trimmed[ldapScheme.Length..];
        else if (trimmed.StartsWith(ldapsScheme, StringComparison.OrdinalIgnoreCase))
            remainder = trimmed[ldapsScheme.Length..];
        else
        {
            error = "The distribution point URL is not an LDAP URL.";
            return false;
        }

        var slash = remainder.IndexOf('/');
        var authority = slash < 0 ? remainder : remainder[..slash];
        var rest = slash < 0 ? string.Empty : remainder[(slash + 1)..];

        var host = authority;
        int? port = null;
        var colon = authority.LastIndexOf(':');
        if (colon >= 0)
        {
            var portText = authority[(colon + 1)..];
            if (int.TryParse(portText, out var parsedPort) && parsedPort is > 0 and <= 65535)
            {
                host = authority[..colon];
                port = parsedPort;
            }
        }

        // dn ? attributes ? scope ? filter ? extensions
        var parts = rest.Split('?');
        var distinguishedName = Unescape(parts[0]);
        if (string.IsNullOrWhiteSpace(distinguishedName))
        {
            error = "The LDAP distribution point URL named no entry.";
            return false;
        }

        var attribute = DefaultAttribute;
        if (parts.Length > 1 && !string.IsNullOrWhiteSpace(parts[1]))
        {
            // Only the first attribute matters: a CDP entry holds the CRL in one.
            var first = Unescape(parts[1]).Split(',')[0].Trim();
            var option = first.IndexOf(';');
            if (option >= 0)
                first = first[..option];
            if (!string.IsNullOrWhiteSpace(first))
                attribute = first;
        }

        var scope = "base";
        if (parts.Length > 2 && !string.IsNullOrWhiteSpace(parts[2]))
            scope = Unescape(parts[2]).Trim().ToLowerInvariant();

        var filter = "(objectClass=*)";
        if (parts.Length > 3 && !string.IsNullOrWhiteSpace(parts[3]))
        {
            var raw = Unescape(parts[3]).Trim();
            // ADCS writes the filter without its outer parentheses, which is
            // legal in a URL and refused by a directory searcher.
            filter = raw.StartsWith('(') ? raw : $"({raw})";
        }

        parsed = new LdapCdpUrl(host, port, distinguishedName, attribute, scope, filter);
        return true;
    }

    private static string Unescape(string value)
    {
        // Literal spaces are common in what ADCS writes, and Uri.UnescapeDataString
        // leaves them alone, so one call covers both spellings.
        try
        {
            return Uri.UnescapeDataString(value).Trim();
        }
        catch (UriFormatException)
        {
            return value.Trim();
        }
    }
}

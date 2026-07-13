using System.Net.NetworkInformation;
using Microsoft.Extensions.Configuration;

namespace Certus.Core.Setup;

/// <summary>
/// Builds the external URL the setup wizard prefills into the Server URL
/// field: the machine's DNS name plus the port the service actually listens
/// on. The port is always written out explicitly, because a URL without one
/// sends ACME clients to the scheme default port, which the service does not
/// listen on unless a proxy forwards it (the issue #89 trap).
///
/// The suggestion is a starting point, not a decision: the field stays
/// editable and the admin still validates it, so a wrong guess (multi homed
/// hosts, DNS aliases, reverse proxies) costs nothing.
/// </summary>
public static class ServerUrlSuggestion
{
    /// <summary>The HTTPS port appsettings.json ships, used when no endpoint can be parsed.</summary>
    private const int DefaultHttpsPort = 5001;

    /// <summary>
    /// Build the suggestion from the live host: DNS name from the machine's
    /// IP configuration and the listening port from the host configuration.
    /// </summary>
    public static string Build(IConfiguration configuration)
    {
        var ip = IPGlobalProperties.GetIPGlobalProperties();
        return Build(
            configuration["Kestrel:Endpoints:Https:Url"],
            configuration["Kestrel:Endpoints:Http:Url"],
            configuration["urls"],
            ip.HostName,
            ip.DomainName);
    }

    /// <summary>
    /// Pure core of <see cref="Build(IConfiguration)"/>. Prefers the HTTPS
    /// endpoint, then an https entry from the semicolon separated "urls"
    /// value (development hosts), then the HTTP endpoint, and finally falls
    /// back to https on the shipped default port.
    /// </summary>
    internal static string Build(
        string? httpsEndpointUrl,
        string? httpEndpointUrl,
        string? urls,
        string hostName,
        string domainName)
    {
        var fqdn = BuildFqdn(hostName, domainName);

        if (TryParseAuthority(httpsEndpointUrl, "https", out var httpsPort))
            return $"https://{fqdn}:{httpsPort}";

        foreach (var candidate in SplitUrls(urls))
        {
            if (TryParseAuthority(candidate, "https", out var urlsPort))
                return $"https://{fqdn}:{urlsPort}";
        }

        if (TryParseAuthority(httpEndpointUrl, "http", out var httpPort))
            return $"http://{fqdn}:{httpPort}";

        return $"https://{fqdn}:{DefaultHttpsPort}";
    }

    /// <summary>
    /// The machine's DNS name: host name joined with the primary DNS domain
    /// when one is set and the host name is not already fully qualified.
    /// Lowercase, since DNS names are case insensitive and certificates and
    /// URLs conventionally use lowercase.
    /// </summary>
    internal static string BuildFqdn(string hostName, string domainName)
    {
        var host = hostName.Trim();
        var domain = domainName.Trim();

        var fqdn = string.IsNullOrEmpty(domain) || host.Contains('.')
            ? host
            : $"{host}.{domain}";

        return fqdn.ToLowerInvariant();
    }

    /// <summary>
    /// Extract the port from a Kestrel endpoint URL of the given scheme.
    /// Kestrel accepts the wildcard hosts "*" and "+", which
    /// <see cref="Uri"/> rejects, so those are substituted before parsing.
    /// </summary>
    internal static bool TryParseAuthority(string? endpointUrl, string scheme, out int port)
    {
        port = 0;
        if (string.IsNullOrWhiteSpace(endpointUrl))
            return false;

        var sanitized = endpointUrl.Trim()
            .Replace("://*", "://0.0.0.0")
            .Replace("://+", "://0.0.0.0");

        if (!Uri.TryCreate(sanitized, UriKind.Absolute, out var uri))
            return false;

        if (!string.Equals(uri.Scheme, scheme, StringComparison.OrdinalIgnoreCase))
            return false;

        port = uri.Port;
        return true;
    }

    private static IEnumerable<string> SplitUrls(string? urls)
    {
        return string.IsNullOrWhiteSpace(urls)
            ? Array.Empty<string>()
            : urls.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }
}

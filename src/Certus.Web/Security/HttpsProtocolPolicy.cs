using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Configuration;

namespace Certus.Web.Security;

/// <summary>
/// The TLS protocols every HTTPS endpoint Kestrel serves will negotiate: TLS 1.2
/// and TLS 1.3, nothing older (issue #484, SEC-N1).
///
/// Without an explicit <see cref="HttpsConnectionAdapterOptions.SslProtocols"/>
/// Kestrel hands <see cref="SslProtocols.None"/> to SslStream, which lets the
/// operating system choose, and on the lab's Server 2025 hosts schannel then
/// completed TLS 1.0 and TLS 1.1 handshakes. The dashboard carries Windows
/// Integrated Authentication over that endpoint, and a certificate issuing
/// product should not depend on the host having been hardened, so the floor is
/// pinned here rather than left to the registry.
///
/// <para>
/// TLS 1.3 stays in the set for Server 2019, whose schannel has none. Measured
/// on lab 2019 (build 17763.3650) on 2026-10-07: the pinned endpoint negotiated
/// TLS 1.2 with every client that offered it, and only a client offering TLS
/// 1.3 alone failed, exactly as it does without the pin.
/// </para>
///
/// <para>
/// How Kestrel 10 layers this against configuration, read from its own
/// <c>TlsConfigurationLoader</c>: <c>Kestrel:EndpointDefaults:SslProtocols</c> is
/// applied first and this pin overwrites it, then an explicit
/// <c>Kestrel:Endpoints:&lt;name&gt;:SslProtocols</c> overwrites this pin. So the
/// floor holds unless an administrator names the protocols on the endpoint
/// itself, which is a deliberate act and theirs to take.
/// </para>
/// </summary>
public static class HttpsProtocolPolicy
{
    /// <summary>The protocols an HTTPS endpoint will negotiate.</summary>
    public const SslProtocols Allowed = SslProtocols.Tls12 | SslProtocols.Tls13;

    /// <summary>
    /// Install the HTTPS defaults: the protocol floor, and the server certificate
    /// when the host resolved one in code.
    /// </summary>
    /// <remarks>
    /// <see cref="KestrelServerOptions.ConfigureHttpsDefaults"/> replaces the
    /// delegate it was given before rather than adding to it, so a host must make
    /// exactly one such call and it must be this one. Setting the certificate in a
    /// second call would silently drop the floor, which is why the certificate
    /// rides along here.
    /// </remarks>
    /// <param name="kestrel">The server options to configure.</param>
    /// <param name="serverCertificate">
    /// The certificate to serve, or null to leave the choice to the endpoint
    /// configuration (a certificate path) or Kestrel's own fallback.
    /// </param>
    public static void Apply(KestrelServerOptions kestrel, X509Certificate2? serverCertificate = null)
    {
        ArgumentNullException.ThrowIfNull(kestrel);

        kestrel.ConfigureHttpsDefaults(https =>
        {
            https.SslProtocols = Allowed;
            if (serverCertificate is not null)
                https.ServerCertificate = serverCertificate;
        });
    }

    /// <summary>
    /// The protocols each HTTPS endpoint in configuration will negotiate, so the
    /// service can say so in its log on every start. That log line is the field
    /// witness: the floor can be overridden in <c>settings.json</c>, and nothing
    /// else on the box shows whether it was.
    /// </summary>
    /// <remarks>
    /// An endpoint is HTTPS when its <c>Url</c> starts with <c>https://</c>, the
    /// test Kestrel applies. Its set is <see cref="Allowed"/> unless
    /// <c>Kestrel:Endpoints:&lt;name&gt;:SslProtocols</c> names one, which wins as
    /// the class remarks describe. Protocols named for one host name under
    /// <c>Kestrel:Endpoints:&lt;name&gt;:Sni</c> are not read; the product
    /// configures no SNI, and an administrator who does has gone past what this
    /// line reports.
    /// </remarks>
    /// <param name="configuration">The host's configuration, after every source is added.</param>
    public static IReadOnlyList<HttpsEndpointProtocols> Describe(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var endpoints = new List<HttpsEndpointProtocols>();
        foreach (var endpoint in configuration.GetSection("Kestrel:Endpoints").GetChildren())
        {
            var url = endpoint["Url"];
            if (url is null || !url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                continue;

            var named = ReadProtocols(endpoint.GetSection("SslProtocols"));
            endpoints.Add(new HttpsEndpointProtocols(endpoint.Key, named ?? Allowed, named is not null));
        }

        return endpoints;
    }

    /// <summary>
    /// True when <paramref name="protocols"/> admits anything older than TLS 1.2.
    /// <see cref="SslProtocols.None"/> counts, because it hands the choice back to
    /// Windows, and a default Server 2019 or Server 2025 install then negotiates
    /// TLS 1.0 and TLS 1.1, which is the finding this class exists to close.
    /// </summary>
    public static bool AdmitsBelowFloor(SslProtocols protocols) =>
        protocols == SslProtocols.None || (protocols & ~Allowed) != SslProtocols.None;

    /// <summary>
    /// Reads a protocol list exactly as Kestrel 10's <c>ConfigurationReader</c>
    /// does, so the log can never report a set the server is not using: the
    /// section's children are the list, each is parsed by name with case
    /// ignored and OR'd in, and a value that does not parse is dropped. A list of
    /// nothing but such values is therefore <see cref="SslProtocols.None"/>, and a
    /// scalar with no children is no list at all.
    /// </summary>
    private static SslProtocols? ReadProtocols(IConfigurationSection section)
    {
        var children = section.GetChildren().ToList();
        if (children.Count == 0)
            return null;

        var protocols = SslProtocols.None;
        foreach (var child in children)
        {
            if (Enum.TryParse(child.Value, ignoreCase: true, out SslProtocols parsed))
                protocols |= parsed;
        }

        return protocols;
    }
}

/// <summary>One HTTPS endpoint and the protocols it will negotiate.</summary>
/// <param name="Name">The endpoint's name under <c>Kestrel:Endpoints</c>.</param>
/// <param name="Protocols">The protocols the endpoint hands to SslStream.</param>
/// <param name="NamedOnEndpoint">
/// True when <c>Kestrel:Endpoints:&lt;name&gt;:SslProtocols</c> chose them,
/// replacing <see cref="HttpsProtocolPolicy.Allowed"/>.
/// </param>
public sealed record HttpsEndpointProtocols(string Name, SslProtocols Protocols, bool NamedOnEndpoint);

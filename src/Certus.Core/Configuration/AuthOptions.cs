namespace Certus.Core.Configuration;

/// <summary>
/// Authentication options for the dashboard and setup APIs.
/// Bound from appsettings.json "Auth" section.
/// The ACME surface is unaffected: ACME clients authenticate with JWS
/// signatures, not HTTP authentication.
/// </summary>
public sealed class AuthOptions
{
    public const string SectionName = "Auth";

    /// <summary>Windows Integrated Authentication (Kerberos and NTLM). The default.</summary>
    public const string ModeNegotiate = "Negotiate";

    /// <summary>
    /// No authentication. Allowed only in the Development environment, and
    /// StartupValidator refuses to start when a real CA is configured.
    /// </summary>
    public const string ModeDisabled = "Disabled";

    /// <summary>
    /// Authentication mechanism: "Negotiate" (default) or "Disabled" (local development only).
    /// </summary>
    public string Mode { get; set; } = ModeNegotiate;

    /// <summary>
    /// Windows or Active Directory group whose members may use the dashboard
    /// and setup APIs. When null, the builtin Administrators group
    /// (SID S-1-5-32-544) is used.
    /// </summary>
    public string? AdminGroup { get; set; }

    /// <summary>
    /// Enforce HTTPS (HSTS and HTTP-to-HTTPS redirection) outside Development.
    /// Defaults to true. The lab deploy profile may set this false until its
    /// HTTPS endpoint is bound (SEC-J2).
    /// </summary>
    public bool RequireHttps { get; set; } = true;

    /// <summary>
    /// IP addresses of reverse proxies whose X-Forwarded-For, X-Forwarded-Host, and
    /// X-Forwarded-Proto headers are trusted. Empty (the default) means forwarded
    /// headers are ignored and the direct connection is treated as the client, so the
    /// ACME rate limiter keys on the real peer and ACME URLs use the real host.
    /// Populate this only when Certus runs behind a known reverse proxy, otherwise a
    /// client could spoof its address or the host echoed in ACME URLs.
    /// </summary>
    public string[] TrustedProxies { get; set; } = [];

    /// <summary>True when authentication is disabled (development escape hatch).</summary>
    public bool IsDisabled =>
        string.Equals(Mode, ModeDisabled, StringComparison.OrdinalIgnoreCase);
}

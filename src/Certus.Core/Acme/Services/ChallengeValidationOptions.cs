namespace Certus.Core.Acme.Services;

/// <summary>
/// Configuration for ACME challenge validation network egress and retry behaviour.
/// Stored in the "Certus:Acme:ChallengeValidation" configuration section.
/// </summary>
public sealed class ChallengeValidationOptions
{
    public const string SectionName = "Certus:Acme:ChallengeValidation";

    /// <summary>
    /// Whether the HTTP-01 and TLS-ALPN-01 validators follow HTTP redirects.
    /// Defaults to false so that a challenge server cannot redirect the validator at an
    /// internal address (a server side request forgery).
    /// </summary>
    public bool AllowRedirects { get; set; }

    /// <summary>Block loopback addresses (127.0.0.0/8 and ::1). Defaults to true.</summary>
    public bool BlockLoopback { get; set; } = true;

    /// <summary>
    /// Block link local addresses (169.254.0.0/16 and fe80::/10). That range also carries
    /// the cloud metadata endpoint at 169.254.169.254. Defaults to true.
    /// </summary>
    public bool BlockLinkLocal { get; set; } = true;

    /// <summary>Block IPv6 unique local addresses (fc00::/7). Defaults to true.</summary>
    public bool BlockUniqueLocalIpv6 { get; set; } = true;

    /// <summary>
    /// Extra CIDR ranges to block, for operators who want to fence off more than the
    /// defaults (for example the RFC 1918 private ranges). Each entry is "address/prefix",
    /// for example "10.0.0.0/8". The private ranges are intentionally not blocked by
    /// default because Certus is commonly an internal CA that issues for private names.
    /// </summary>
    public string[] AdditionalBlockedCidrs { get; set; } = [];

    /// <summary>
    /// How many times a challenge whose validation hit a transient transport error is
    /// retried before it is marked invalid. Defaults to 5.
    /// </summary>
    public int MaxValidationAttempts { get; set; } = 5;
}

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
    /// Block the RFC 1918 private ranges (10.0.0.0/8, 172.16.0.0/12, and
    /// 192.168.0.0/16). Defaults to false: Certus is commonly an internal CA that
    /// validates hosts on exactly these ranges, and blocking them by default would
    /// break that primary use case. Turn this on when every validation target is
    /// public, so a challenge cannot steer the validator at internal services
    /// (a server side request forgery).
    /// </summary>
    public bool BlockPrivateRanges { get; set; }

    /// <summary>
    /// Extra CIDR ranges to block, for operators who want to fence off more than the
    /// defaults. Each entry is "address/prefix", for example "100.64.0.0/10" (the
    /// carrier grade NAT range). The RFC 1918 private ranges have their own switch,
    /// <see cref="BlockPrivateRanges"/>; they are intentionally not blocked by default
    /// because Certus is commonly an internal CA that issues for private names.
    /// </summary>
    public string[] AdditionalBlockedCidrs { get; set; } = [];

    /// <summary>
    /// How many times a challenge whose validation hit a transient transport error is
    /// retried before it is marked invalid. Defaults to 5.
    /// </summary>
    public int MaxValidationAttempts { get; set; } = 5;

    /// <summary>
    /// How often the background worker sweeps for challenges in "processing" state,
    /// in seconds. Defaults to 5. The worker clamps the value to a sane range; the
    /// integration tests shrink it so a full device attestation round trip completes
    /// without dead waiting.
    /// </summary>
    public double PollIntervalSeconds { get; set; } = 5;
}

namespace Certus.Core.Security;

/// <summary>
/// Rate limiting configuration for ACME endpoints.
/// </summary>
public sealed class AcmeRateLimitOptions
{
    public const string SectionName = "Certus:RateLimiting";

    /// <summary>Whether rate limiting is enabled. Defaults to true.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Maximum requests per window for new-account endpoints.</summary>
    public int NewAccountLimit { get; set; } = 10;

    /// <summary>Maximum requests per window for new-order endpoints.</summary>
    public int NewOrderLimit { get; set; } = 30;

    /// <summary>Maximum requests per window for general ACME endpoints.</summary>
    public int GeneralLimit { get; set; } = 100;

    /// <summary>Rate limit window in seconds. Defaults to 60.</summary>
    public int WindowSeconds { get; set; } = 60;
}

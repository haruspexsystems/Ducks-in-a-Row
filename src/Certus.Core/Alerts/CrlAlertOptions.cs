namespace Certus.Core.Alerts;

/// <summary>
/// What the CRL monitor watches and how hard it tries.
///
/// The warning thresholds are deliberately not here: a CRL expiring and a
/// certificate expiring are the same question asked about different subjects,
/// and an operator who wants sixty days of notice wants it for both. The ladder
/// is <see cref="AlertOptions.ThresholdDays"/>, shared.
/// </summary>
public sealed class CrlAlertOptions
{
    /// <summary>Whether to watch CRLs at all.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// How often to look, in minutes. The same hour the leaf monitor uses. A CRL
    /// that a CA replaces weekly does not need watching more often than that,
    /// and the read is bounded further by not asking the CA again until the CRL
    /// it already has says it should have been replaced.
    /// </summary>
    public int CheckIntervalMinutes { get; set; } = 60;

    /// <summary>
    /// How long to wait for a distribution point, in seconds. Fifteen is what
    /// MS-WCCE section 3.2.1.4.1.3 gives a CA fetching a CRL for a client, so a
    /// distribution point too slow for this is too slow for the CA as well.
    /// </summary>
    public int FetchTimeoutSeconds { get; set; } = 15;

    /// <summary>
    /// The largest CRL to accept, in bytes. A busy CA's CRL genuinely reaches
    /// megabytes; a distribution point serving hundreds of megabytes is serving
    /// something else.
    /// </summary>
    public int MaxCrlBytes { get; set; } = 32 * 1024 * 1024;
}

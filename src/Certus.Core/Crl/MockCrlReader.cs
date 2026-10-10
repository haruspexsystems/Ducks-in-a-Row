using Certus.Core.Adcs;

namespace Certus.Core.Crl;

/// <summary>
/// The CRL half of the mock CA, so the dev host and the tests that use
/// <see cref="MockAdcsClient"/> have something to monitor.
///
/// It answers with the shape a default Windows CA produces, measured on lab 2019
/// on 2026-09-23: a base CRL published a week ago and replaced every week, with
/// about twelve hours of overlap between the replacement and the expiry, and a
/// delta replaced daily. The numbers matter because the alert rules turn on
/// them, and a mock that produced a year long CRL would exercise the wrong half
/// of those rules on every dev host.
///
/// It publishes no distribution point URL, which keeps the dev host from making
/// an outbound request: the mock CA is not on any network.
/// </summary>
public sealed class MockCrlReader : ICaCrlReader
{
    /// <summary>
    /// Stands in for the key identifier a real CA's CRLs carry. Fixed, so the
    /// dev host keeps one row rather than growing a new one per restart.
    /// </summary>
    private const string MockKeyIdentifier = "00000000000000000000000000000000000000AA";

    private readonly TimeProvider _timeProvider;
    private int _crlNumber = 0x25;

    public MockCrlReader(TimeProvider? timeProvider = null)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>How long ago the current base CRL was published.</summary>
    public TimeSpan BasePublishedAgo { get; set; } = TimeSpan.FromDays(1);

    /// <summary>The base CRL period, the interval the CA replaces it on.</summary>
    public TimeSpan BasePeriod { get; set; } = TimeSpan.FromDays(7);

    /// <summary>
    /// How long a CRL stays usable after the CA meant to replace it. Twelve
    /// hours is what a CA running on the shipped defaults produces.
    /// </summary>
    public TimeSpan Overlap { get; set; } = TimeSpan.FromHours(12);

    /// <summary>Whether the mock CA publishes delta CRLs. Real CAs mostly do.</summary>
    public bool PublishesDelta { get; set; } = true;

    /// <summary>The CPF flags to report, 5 being CPF_BASE | CPF_COMPLETE.</summary>
    public int? PublishFlags { get; set; } = 0x5;

    /// <summary>
    /// The distribution point URLs to claim. Empty by default, so nothing on a
    /// dev host tries to reach a network.
    /// </summary>
    public IReadOnlyList<string> DistributionPointUrls { get; set; } = [];

    /// <summary>Set to have the reader behave like a CA that cannot be reached.</summary>
    public bool ThrowUnavailable { get; set; }

    public Task<CaCrlSnapshot> ReadAsync(CancellationToken cancellationToken = default)
    {
        if (ThrowUnavailable)
        {
            throw new CaUnavailableException(
                "ADCS Certificate Authority is unavailable (mock).");
        }

        var now = _timeProvider.GetUtcNow();
        var crls = new List<CaCrlRecord>
        {
            BuildRecord(isDelta: false, now - BasePublishedAgo, BasePeriod),
        };

        if (PublishesDelta)
        {
            // A delta is published daily and lives a day plus the same overlap.
            crls.Add(BuildRecord(isDelta: true, now - TimeSpan.FromHours(2), TimeSpan.FromDays(1)));
        }

        return Task.FromResult(new CaCrlSnapshot(crls, DistributionPointUrls));
    }

    private CaCrlRecord BuildRecord(bool isDelta, DateTimeOffset thisUpdate, TimeSpan period)
    {
        var nextPublish = thisUpdate + period;
        return new CaCrlRecord(
            KeyIndex: 0,
            IsDelta: isDelta,
            CrlNumberHex: (_crlNumber + (isDelta ? 1 : 0)).ToString("X2"),
            ThisUpdate: thisUpdate,
            NextUpdate: nextPublish + Overlap,
            NextPublish: nextPublish,
            AuthorityKeyIdentifierHex: MockKeyIdentifier,
            PublishFlags: isDelta ? 0x6 : PublishFlags);
    }
}

/// <summary>
/// The CRL reader bound while no CA is configured. Every read answers the way
/// every other CA operation does before the setup wizard has run, so the monitor
/// logs one unavailable CA rather than faulting.
/// </summary>
public sealed class UnconfiguredCrlReader : ICaCrlReader
{
    public Task<CaCrlSnapshot> ReadAsync(CancellationToken cancellationToken = default) =>
        throw new CaUnavailableException(
            "No certificate authority is configured. Run the setup wizard to connect one.");
}

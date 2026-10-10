namespace Certus.Core.Crl;

/// <summary>
/// One CRL the CA itself holds, reduced to the facts a monitor needs.
///
/// The bytes are deliberately absent. The CA hands over a whole CRL, which on a
/// busy estate is megabytes of revocation entries, and none of those entries
/// says when the CRL expires. The reader parses once and passes on the header.
/// </summary>
/// <param name="KeyIndex">
/// Which CA signing certificate published it. A CA renewed with a new key keeps
/// publishing one CRL per key while certificates issued under the old key are
/// still alive, and each of them can lapse on its own.
/// </param>
/// <param name="IsDelta">A delta CRL rather than a base CRL.</param>
/// <param name="CrlNumberHex">The CRL number, which identifies this instance.</param>
/// <param name="ThisUpdate">When the CA issued it.</param>
/// <param name="NextUpdate">When it stops being usable, null if it never does.</param>
/// <param name="NextPublish">
/// When the CA intends to replace it, from Microsoft's Next CRL Publish
/// extension. For a CA that publishes on a timer this is the date that says
/// whether a publish was missed, and nextUpdate only says how long is left
/// after that.
/// </param>
/// <param name="AuthorityKeyIdentifierHex">
/// The key identifier of the CA key that signed it. This is what tells the CRLs
/// of a renewed CA apart, and it is also what makes a copy read from the CA and
/// a copy read from a distribution point recognisable as the same CRL.
/// </param>
/// <param name="PublishFlags">
/// The CPF flags from CR_PROP_BASECRLPUBLISHSTATUS or
/// CR_PROP_DELTACRLPUBLISHSTATUS. A CA can be perfectly healthy and still be
/// failing to write its CRL to a file share or to the directory, and this is the
/// only thing that says so.
/// </param>
public sealed record CaCrlRecord(
    int KeyIndex,
    bool IsDelta,
    string? CrlNumberHex,
    DateTimeOffset ThisUpdate,
    DateTimeOffset? NextUpdate,
    DateTimeOffset? NextPublish,
    string? AuthorityKeyIdentifierHex,
    int? PublishFlags);

/// <summary>
/// What the configured CA says about its own CRLs.
/// </summary>
/// <param name="Crls">One entry per signing key and kind.</param>
/// <param name="DistributionPointUrls">
/// The URLs the CA writes into the certificates it issues, so its own CRL can be
/// read back from where its clients read it. Empty when the CA publishes none.
/// </param>
public sealed record CaCrlSnapshot(
    IReadOnlyList<CaCrlRecord> Crls,
    IReadOnlyList<string> DistributionPointUrls)
{
    public static readonly CaCrlSnapshot Empty = new([], []);
}

/// <summary>
/// Reads the configured CA's own CRLs from the CA itself.
///
/// Deliberately a separate interface from <see cref="Certus.Core.Adcs.IAdcsClient"/>.
/// That one is implemented by twelve classes, nine of them test doubles for
/// paths that have nothing to do with CRLs, and a method added there would have
/// to be implemented in all of them. A CRL monitor is also the only caller this
/// will ever have.
/// </summary>
public interface ICaCrlReader
{
    /// <summary>
    /// Reads every CRL the CA currently holds. Best effort in the sense the
    /// directory readers are: it throws for a CA that cannot be reached or that
    /// refuses the caller, because the monitor treats those differently from a
    /// CA that answered, but it never throws over a single unreadable CRL.
    /// </summary>
    /// <exception cref="Certus.Core.Adcs.CaUnavailableException">The CA could not be reached.</exception>
    /// <exception cref="Certus.Core.Adcs.CaAccessDeniedException">The CA refused the service account.</exception>
    Task<CaCrlSnapshot> ReadAsync(CancellationToken cancellationToken = default);
}

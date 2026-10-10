namespace Certus.Core.Crl;

/// <summary>
/// What reading one distribution point produced.
///
/// A failure is an ordinary result rather than an exception, because a
/// distribution point that cannot be reached is a normal state of the world:
/// an HTTP location on a segment this server cannot route to, or a directory
/// entry that was never published. The monitor records it, shows it, and keeps
/// alerting on the last copy it did read.
/// </summary>
/// <param name="Ok">Whether anything was read.</param>
/// <param name="Crls">
/// The encoded CRLs. HTTP always yields one; a directory attribute is multi
/// valued and can hold one per CA key, so every value comes back and the caller
/// decides which belong to the key it is watching.
/// </param>
/// <param name="ETag">The HTTP entity tag, kept so the next read can be conditional.</param>
/// <param name="LastModified">The HTTP last modified time, kept for the same reason.</param>
/// <param name="NotModified">
/// The server answered 304, so the copy already stored is current. This is
/// success with nothing to parse, and it is what keeps an hourly check off the
/// wire for a CRL that can be megabytes.
/// </param>
/// <param name="Error">Why nothing was read, for the card and the log.</param>
public sealed record CrlFetchResult(
    bool Ok,
    IReadOnlyList<byte[]> Crls,
    string? ETag,
    DateTimeOffset? LastModified,
    bool NotModified,
    string? Error)
{
    /// <summary>Nothing was read, and this is why.</summary>
    public static CrlFetchResult Failure(string error) =>
        new(false, [], null, null, false, error);

    /// <summary>The stored copy is still current.</summary>
    public static CrlFetchResult Unchanged() =>
        new(true, [], null, null, true, null);

    /// <summary>One or more CRLs were read.</summary>
    public static CrlFetchResult Success(
        IReadOnlyList<byte[]> crls,
        string? eTag = null,
        DateTimeOffset? lastModified = null) =>
        new(true, crls, eTag, lastModified, false, null);
}

namespace Certus.Core.Data.Entities;

/// <summary>
/// Failed dashboard sign ins from one source address in one hour (issue #634,
/// CRA risk R07, Annex I (2)(d) "reporting of possible unauthorised access").
/// A 401 that carried credentials and still failed, or a 403 for an
/// authenticated caller outside the administrator group, on an <c>/api</c>
/// route. Counted per source and per hour rather than stored one row per
/// attempt, so a source hammering the login cannot grow the table faster than
/// one row an hour, and so the trail page can say "this many from that
/// address" without a scan.
///
/// <para>The source address is the only datum about the caller, which the
/// policy rejection table already stores for ACME clients. Nothing names a
/// user: a failed sign in has no trusted identity to name.</para>
/// </summary>
public class AdminSignInFailure
{
    /// <summary>Internal database ID.</summary>
    public int Id { get; set; }

    /// <summary>The client address the attempts came from, or "unknown" when the connection carried none.</summary>
    public string SourceAddress { get; set; } = string.Empty;

    /// <summary>401 (credentials refused) or 403 (authenticated, not an administrator).</summary>
    public int StatusCode { get; set; }

    /// <summary>The start of the hour the attempts fall in (UTC).</summary>
    public DateTime BucketStart { get; set; }

    /// <summary>How many attempts the row counts.</summary>
    public int Count { get; set; }

    /// <summary>The first attempt in the hour (UTC).</summary>
    public DateTime FirstAt { get; set; }

    /// <summary>The latest attempt in the hour (UTC).</summary>
    public DateTime LastAt { get; set; }
}

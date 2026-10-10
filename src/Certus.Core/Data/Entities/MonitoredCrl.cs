namespace Certus.Core.Data.Entities;

/// <summary>
/// The last thing known about one CRL, at one of the places it is published.
///
/// It is stored rather than held in memory for two reasons. The card shows it,
/// and a monitor that has lost sight of a CRL still has to warn about it: when
/// every copy of the root's CRL becomes unreadable, the alerts go on firing
/// against the last copy that was read, flagged as stale, because an unreachable
/// distribution point is not evidence that the CRL was renewed. A restart would
/// otherwise lose exactly the knowledge that matters most.
///
/// One row per (scope, issuer key, kind, source). The same CRL published to a
/// directory and to a web server is two rows, which is the point: an
/// administrator who renews a root CRL and copies it to one of the two leaves
/// the other serving a CRL that expires, and nothing else in the estate will say
/// so.
/// </summary>
public class MonitoredCrl
{
    /// <summary>Internal database ID.</summary>
    public int Id { get; set; }

    /// <summary>
    /// "issuing" for a CRL the configured CA publishes itself, "parent" for one
    /// that covers a certificate above it in the chain, which on a normal estate
    /// is the offline root's.
    /// </summary>
    public string Scope { get; set; } = string.Empty;

    /// <summary>
    /// The key identifier of the CA certificate expected to have signed this
    /// CRL, as hex. Taken from the chain rather than from the CRL, because a
    /// distribution point that has never answered still needs a row, and because
    /// it is what the CRL is verified against when one does.
    /// </summary>
    public string IssuerKeyId { get; set; } = string.Empty;

    /// <summary>The issuing CA, for display. Sanitized on the way in.</summary>
    public string IssuerName { get; set; } = string.Empty;

    /// <summary>"base" or "delta".</summary>
    public string Kind { get; set; } = string.Empty;

    /// <summary>
    /// Where this copy was read: "ca" for the certificate authority itself, or
    /// the distribution point URL.
    /// </summary>
    public string Source { get; set; } = string.Empty;

    /// <summary>
    /// The CRL number of the copy last read, as hex. Null when nothing has ever
    /// been read from this source.
    /// </summary>
    public string? CrlNumber { get; set; }

    /// <summary>
    /// What identifies the CRL instance for alert history: the CRL number when
    /// there is one, and the publication instant when there is not. A CRL that is
    /// replaced gets a new one, which is what re-arms every threshold.
    /// </summary>
    public string? InstanceKey { get; set; }

    /// <summary>When the CA issued the copy last read.</summary>
    public DateTime? ThisUpdate { get; set; }

    /// <summary>When that copy stops being usable.</summary>
    public DateTime? NextUpdate { get; set; }

    /// <summary>
    /// When the CA said it would replace that copy, from Microsoft's Next CRL
    /// Publish extension. Null on a CRL from a CA that does not stamp it.
    /// </summary>
    public DateTime? NextPublish { get; set; }

    /// <summary>
    /// Whether the issuer replaces this CRL on a timer. It decides which rule
    /// applies: a ladder of advance warnings for a CRL somebody has to publish
    /// by hand, and a missed publish alert for one a CA replaces itself.
    /// </summary>
    public bool AutoPublished { get; set; }

    /// <summary>
    /// What the signature check concluded: "verified", "failed", "unsupported",
    /// "no-key", or null for a copy read from the CA over its own authenticated
    /// channel, where there is nothing to check it against and nothing to gain.
    /// </summary>
    public string? SignatureStatus { get; set; }

    /// <summary>
    /// The CPF publish flags the CA reported, for the CA's own CRLs. A CA that
    /// is running perfectly can still be failing to write its CRL where its
    /// clients read it, and this is what says so.
    /// </summary>
    public int? PublishFlags { get; set; }

    /// <summary>When this source was last looked at, whether or not it answered.</summary>
    public DateTime LastCheckedAt { get; set; }

    /// <summary>When this source last answered with a CRL.</summary>
    public DateTime? LastReadAt { get; set; }

    /// <summary>Why the last look failed, redacted and capped. Null when it did not.</summary>
    public string? LastError { get; set; }

    /// <summary>
    /// The HTTP entity tag of the copy last read, so the next read can be
    /// conditional and cost a few bytes instead of a whole CRL.
    /// </summary>
    public string? ETag { get; set; }

    /// <summary>The HTTP last modified time, used the same way.</summary>
    public DateTime? LastModified { get; set; }
}

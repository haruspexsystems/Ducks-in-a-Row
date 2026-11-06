using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Certus.Core.Adcs;
using Certus.Core.Configuration;

namespace Certus.Core.Setup;

/// <summary>
/// What the service needs to know about one certificate in LocalMachine\My to
/// decide which one to serve. Built by <see cref="HttpsCertificateFollow.Describe"/>
/// so the decision itself can be tested without a certificate store.
/// </summary>
/// <param name="Thumbprint">The certificate's thumbprint, as the store reports it.</param>
/// <param name="SubjectIdentity">
/// The subject as RFC 4514 renders it, or, for a certificate with an empty
/// subject, its subject alternative names, sorted and prefixed "san:". Two
/// certificates with the same identity were issued to the same name.
/// </param>
/// <param name="Template">The template the certificate names, or null.</param>
/// <param name="NotBefore">Start of validity.</param>
/// <param name="NotAfter">End of validity.</param>
/// <param name="HasPrivateKey">Whether the store holds the private key.</param>
/// <param name="Archived">
/// Whether the certificate is archived in the store, which is what Windows
/// autoenrolment does to the certificate a renewal supersedes.
/// </param>
/// <param name="ServerAuthUsable">
/// Whether a TLS client would accept it for a server: no enhanced key usage
/// extension at all, or one naming Server Authentication or any purpose.
/// </param>
/// <param name="IsCertificateAuthority">Whether basic constraints mark it as a CA.</param>
/// <param name="KeyUsable">
/// Whether this process can sign with the private key, which a TLS handshake
/// needs. The store can report a key the service account cannot use, and a
/// certificate with such a key would stop the service binding HTTPS. Tested only
/// for a certificate that could otherwise be served, so startup signs with as few
/// keys as it can.
/// </param>
public sealed record HttpsCertificateFacts(
    string Thumbprint,
    string SubjectIdentity,
    CertificateTemplateIdentity? Template,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    bool HasPrivateKey,
    bool Archived,
    bool ServerAuthUsable,
    bool IsCertificateAuthority,
    bool KeyUsable = true);

/// <summary>How the service settled on the HTTPS certificate it serves.</summary>
public enum HttpsCertificateChoiceOutcome
{
    /// <summary>The pinned certificate is current, and is served.</summary>
    Pinned,

    /// <summary>
    /// The pinned certificate was archived or has expired, and a successor with
    /// the same subject and template is served instead.
    /// </summary>
    Followed,

    /// <summary>
    /// The pinned certificate was archived but is still valid and no successor
    /// was found, so it is still served.
    /// </summary>
    ArchivedNoSuccessor,

    /// <summary>No certificate in the store has the pinned thumbprint.</summary>
    NotInStore,

    /// <summary>The pinned certificate is current but its private key is missing.</summary>
    NoPrivateKey,

    /// <summary>The pinned certificate expired and no successor was found.</summary>
    ExpiredNoSuccessor,

    /// <summary>
    /// The pinned certificate expired and names no template, so there is nothing
    /// to match a successor against.
    /// </summary>
    NoIdentityToFollow,
}

/// <summary>
/// The decision: which certificate to serve, if any, and why.
/// </summary>
/// <param name="Outcome">How the decision was reached.</param>
/// <param name="ServeThumbprint">
/// The thumbprint to serve, or null to fall back to the self signed certificate.
/// </param>
/// <param name="PinnedThumbprint">The thumbprint configuration pinned, normalized.</param>
/// <param name="Reason">One sentence for the service log.</param>
public sealed record HttpsCertificateChoice(
    HttpsCertificateChoiceOutcome Outcome,
    string? ServeThumbprint,
    string PinnedThumbprint,
    string Reason);

/// <summary>
/// Follows a pinned HTTPS certificate across a renewal (issue #471).
///
/// The service pins its HTTPS certificate by thumbprint, and a renewal issues a
/// new certificate under a new thumbprint. Before this, the pinned certificate
/// stopped being found the moment it was superseded or expired, and the next
/// boot served the self signed certificate. In monitor mode the service never
/// enrols its own certificate, so an autoenrolled one is the normal case and
/// the renewal is somebody else's.
///
/// The rule: when the pinned certificate has been archived or has expired, serve
/// the newest certificate issued after it with the same subject and the same
/// template, provided it is valid now, carries its private key, suits a TLS
/// server and is not a CA certificate. The reference identity comes only from
/// the pinned certificate itself, which is why the store is opened with
/// archived certificates included. Nothing about it is recorded anywhere else,
/// because four separate writers set the thumbprint and every one of them would
/// have to keep a second record in step, and a thumbprint changed by hand
/// without its record would follow the old identity to the wrong certificate.
///
/// The store hides an archived certificate unless it is opened with
/// <see cref="OpenFlags.IncludeArchived"/>: measured on .NET 10.0.12 on
/// 2026-10-11, an archived certificate was absent from a plain open and present,
/// reading Archived, with the flag. That Windows autoenrolment archives the
/// certificate a renewal supersedes, rather than deleting it, is still a belief,
/// not a measurement. If the pinned certificate is gone altogether there is
/// nothing to follow from, and the service falls back as it always has, saying
/// why.
///
/// The choice is taken once, at startup. A service that runs across the old
/// certificate's expiry keeps serving it until it restarts.
/// </summary>
public static class HttpsCertificateFollow
{
    private const string AnyPurposeEku = "2.5.29.37.0";

    /// <summary>
    /// A thumbprint reduced to its hexadecimal digits, upper case. A thumbprint
    /// copied out of the certificates console carries spaces and, often, an
    /// invisible left to right mark in front, and neither is part of it.
    /// </summary>
    public static string NormalizeThumbprint(string thumbprint)
    {
        ArgumentNullException.ThrowIfNull(thumbprint);
        return new string(thumbprint.Where(Uri.IsHexDigit).ToArray()).ToUpperInvariant();
    }

    /// <summary>Reads the facts the decision needs off a store certificate.</summary>
    public static HttpsCertificateFacts Describe(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        var subject = certificate.SubjectName.Name;
        var subjectIdentity = string.IsNullOrWhiteSpace(subject)
            ? "san:" + string.Join(",", TlsCertificateEnroller.GetSubjectNames(certificate)
                .Select(name => name.ToLowerInvariant())
                .OrderBy(name => name, StringComparer.Ordinal))
            : subject;

        var serverAuthUsable = true;
        var isCertificateAuthority = false;
        foreach (var extension in certificate.Extensions)
        {
            if (extension is X509EnhancedKeyUsageExtension eku)
            {
                serverAuthUsable = eku.EnhancedKeyUsages
                    .Cast<System.Security.Cryptography.Oid>()
                    .Any(oid => oid.Value is SetupService.ServerAuthEku or AnyPurposeEku);
            }
            else if (extension is X509BasicConstraintsExtension constraints)
            {
                isCertificateAuthority = constraints.CertificateAuthority;
            }
        }

        var archived = ReadArchived(certificate);
        var hasPrivateKey = certificate.HasPrivateKey;
        return new HttpsCertificateFacts(
            Thumbprint: certificate.Thumbprint,
            SubjectIdentity: subjectIdentity,
            Template: CertificateTemplateExtensionReader.ReadFrom(certificate),
            NotBefore: new DateTimeOffset(certificate.NotBefore),
            NotAfter: new DateTimeOffset(certificate.NotAfter),
            HasPrivateKey: hasPrivateKey,
            Archived: archived,
            ServerAuthUsable: serverAuthUsable,
            IsCertificateAuthority: isCertificateAuthority,
            KeyUsable: hasPrivateKey && !archived && serverAuthUsable && !isCertificateAuthority
                       && MachineCertificateChoices.KeySigns(certificate));
    }

    /// <summary>
    /// Decide which certificate to serve for <paramref name="configuredThumbprint"/>,
    /// given every certificate in the store, archived ones included.
    /// </summary>
    public static HttpsCertificateChoice Choose(
        string configuredThumbprint,
        IReadOnlyList<HttpsCertificateFacts> store,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(configuredThumbprint);
        ArgumentNullException.ThrowIfNull(store);

        var pinnedThumbprint = NormalizeThumbprint(configuredThumbprint);
        var pinned = store.FirstOrDefault(c =>
            string.Equals(NormalizeThumbprint(c.Thumbprint), pinnedThumbprint, StringComparison.Ordinal));

        if (pinned is null)
        {
            return new HttpsCertificateChoice(
                HttpsCertificateChoiceOutcome.NotInStore, null, pinnedThumbprint,
                $"No certificate in LocalMachine\\My, archived ones included, has the configured " +
                $"thumbprint {pinnedThumbprint}, so there is nothing to follow from.");
        }

        var expired = pinned.NotAfter <= now;
        if (!pinned.Archived && !expired)
        {
            return pinned.HasPrivateKey
                ? new HttpsCertificateChoice(
                    HttpsCertificateChoiceOutcome.Pinned, pinned.Thumbprint, pinnedThumbprint,
                    $"The configured certificate {pinnedThumbprint} is current.")
                : new HttpsCertificateChoice(
                    HttpsCertificateChoiceOutcome.NoPrivateKey, null, pinnedThumbprint,
                    $"The configured certificate {pinnedThumbprint} has no private key.");
        }

        var successor = FindSuccessor(pinned, store, now);
        if (successor is not null)
        {
            var why = pinned.Archived ? "was archived" : $"expired {pinned.NotAfter:u}";
            return new HttpsCertificateChoice(
                HttpsCertificateChoiceOutcome.Followed, successor.Thumbprint, pinnedThumbprint,
                $"The configured certificate {pinnedThumbprint} {why}; serving {successor.Thumbprint}, " +
                $"issued after it to the same subject from the same template " +
                $"({pinned.Template!.Describe()}), valid until {successor.NotAfter:u}.");
        }

        if (!expired)
        {
            return pinned.HasPrivateKey
                ? new HttpsCertificateChoice(
                    HttpsCertificateChoiceOutcome.ArchivedNoSuccessor, pinned.Thumbprint, pinnedThumbprint,
                    $"The configured certificate {pinnedThumbprint} was archived but is valid until " +
                    $"{pinned.NotAfter:u}, and no certificate issued after it to the same subject from " +
                    "the same template was found, so it is still served.")
                : new HttpsCertificateChoice(
                    HttpsCertificateChoiceOutcome.NoPrivateKey, null, pinnedThumbprint,
                    $"The configured certificate {pinnedThumbprint} was archived and has no private " +
                    "key, and no certificate issued after it to the same subject from the same " +
                    "template was found.");
        }

        if (pinned.Template is null)
        {
            return new HttpsCertificateChoice(
                HttpsCertificateChoiceOutcome.NoIdentityToFollow, null, pinnedThumbprint,
                $"The configured certificate {pinnedThumbprint} is no longer usable and names no " +
                "certificate template, so no successor can be matched to it.");
        }

        return new HttpsCertificateChoice(
            HttpsCertificateChoiceOutcome.ExpiredNoSuccessor, null, pinnedThumbprint,
            $"The configured certificate {pinnedThumbprint} is no longer usable, and no valid " +
            $"certificate issued after it to the same subject from the same template " +
            $"({pinned.Template.Describe()}) carries its private key.");
    }

    private static HttpsCertificateFacts? FindSuccessor(
        HttpsCertificateFacts pinned,
        IReadOnlyList<HttpsCertificateFacts> store,
        DateTimeOffset now)
    {
        if (pinned.Template is null || string.IsNullOrWhiteSpace(pinned.SubjectIdentity)
            || pinned.SubjectIdentity == "san:")
        {
            return null;
        }

        return store
            .Where(c =>
                !string.Equals(c.Thumbprint, pinned.Thumbprint, StringComparison.OrdinalIgnoreCase)
                && !c.Archived
                && c.HasPrivateKey
                && c.KeyUsable
                && c.NotBefore <= now && now < c.NotAfter
                // Issued after the pinned one, so a follow can never step back to an
                // older certificate that happens to still be valid.
                && c.NotBefore > pinned.NotBefore
                && c.ServerAuthUsable
                && !c.IsCertificateAuthority
                && string.Equals(c.SubjectIdentity, pinned.SubjectIdentity, StringComparison.OrdinalIgnoreCase)
                && c.Template is not null
                && pinned.Template.SameTemplateAs(c.Template))
            .OrderByDescending(c => c.NotBefore)
            .ThenByDescending(c => c.NotAfter)
            .ThenBy(c => c.Thumbprint, StringComparer.Ordinal)
            .FirstOrDefault();
    }

    /// <summary>
    /// Record the followed certificate in the settings overlay, so the settings
    /// page and the automatic renewal see the certificate actually served rather
    /// than the one it replaced.
    ///
    /// Compare and swap: it writes only when the overlay holds exactly the pinned
    /// thumbprint, and keeps every other key. It never creates the overlay, so a
    /// thumbprint that came from appsettings.json, an environment variable or the
    /// command line is left where it is, and an overlay the service does not
    /// trust reads as empty and is not touched. Returns whether it wrote;
    /// <paramref name="failure"/> carries a write that was attempted and failed.
    /// </summary>
    public static bool TryRepin(
        string overlayPath,
        string pinnedThumbprint,
        string followedThumbprint,
        out string? failure)
    {
        ArgumentNullException.ThrowIfNull(overlayPath);
        ArgumentNullException.ThrowIfNull(pinnedThumbprint);
        ArgumentNullException.ThrowIfNull(followedThumbprint);

        failure = null;
        var pinned = NormalizeThumbprint(pinnedThumbprint);

        try
        {
            // The check runs inside Mutate's lock, so it is a true compare and
            // swap, and declining throws rather than returning the record
            // unchanged, because Mutate saves whatever the change returns: an
            // unchanged return would still create a missing overlay and rewrite
            // an untrusted one, which reads as empty.
            SettingsOverlay.Mutate(overlayPath, current =>
                HoldsThumbprint(current, pinned)
                    ? current with { HttpsCertificateThumbprint = followedThumbprint }
                    : throw new RepinDeclinedException());
            return true;
        }
        catch (RepinDeclinedException)
        {
            return false;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            failure = ex.Message;
            return false;
        }
    }

    /// <summary>
    /// Aborts a re-pin from inside <see cref="SettingsOverlay.Mutate"/> before it
    /// saves anything. Never leaves <see cref="TryRepin"/>.
    /// </summary>
    private sealed class RepinDeclinedException : Exception;

    private static bool HoldsThumbprint(SettingsOverlay.OverlaySettings overlay, string normalizedThumbprint) =>
        overlay.HttpsCertificateThumbprint is { } recorded
        && string.Equals(NormalizeThumbprint(recorded), normalizedThumbprint, StringComparison.Ordinal);

    private static bool ReadArchived(X509Certificate2 certificate)
    {
        try
        {
            return certificate.Archived;
        }
        catch (PlatformNotSupportedException)
        {
            return false;
        }
    }
}

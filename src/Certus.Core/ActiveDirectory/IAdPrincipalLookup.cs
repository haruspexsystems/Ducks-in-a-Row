namespace Certus.Core.ActiveDirectory;

/// <summary>
/// An Active Directory security principal, as offered by the EAB credential
/// owner picker (issue #132).
/// </summary>
/// <param name="Sid">The security identifier in SDDL form ("S-1-5-21-...").</param>
/// <param name="Name">The account name (<c>sAMAccountName</c>, falling back to <c>cn</c>).</param>
/// <param name="Type">"user", "computer", "group", or "service account".</param>
/// <param name="DistinguishedName">The full DN, for disambiguation in the picker; may be null.</param>
public sealed record AdPrincipal(
    string Sid,
    string Name,
    string Type,
    string? DistinguishedName);

/// <summary>
/// Searches and resolves Active Directory security principals for the EAB
/// credential owner link. The link is display and audit only; nothing
/// enforces against it, so this lookup is best effort by contract: a host
/// that is not domain joined, an unreachable directory, or insufficient
/// rights yield an empty search result or a null resolution, never an
/// exception. The real implementation lives in Certus.Adcs (Windows only);
/// the dev host and tests use <see cref="MockAdPrincipalLookup"/>.
/// </summary>
public interface IAdPrincipalLookup
{
    /// <summary>
    /// Finds users, computers, groups, and managed service accounts whose
    /// account name or common name starts with <paramref name="query"/>.
    /// Returns a short capped list (implementations cap at roughly 20);
    /// empty for a blank query or any directory failure.
    /// </summary>
    Task<IReadOnlyList<AdPrincipal>> SearchAsync(
        string query, CancellationToken cancellationToken = default);

    /// <summary>
    /// Resolves one SID back to its principal, or null when the SID is not
    /// well formed, does not exist, or the directory cannot be reached. The
    /// admin endpoint calls this before storing a link, so the stored name
    /// and type are the directory's answer, not the client's claim.
    /// </summary>
    Task<AdPrincipal?> ResolveSidAsync(
        string sid, CancellationToken cancellationToken = default);
}

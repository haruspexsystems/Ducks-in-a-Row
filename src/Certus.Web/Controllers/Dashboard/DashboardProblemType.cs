namespace Certus.Web.Controllers.Dashboard;

/// <summary>
/// Problem type URIs (RFC 9457, which replaced RFC 7807) for the problem
/// documents the dashboard API returns. Each one resolves to a short page at
/// https://ducksinarow.dev/problems/&lt;slug&gt;, published by GitHub Pages
/// from the gh-pages branch of the public haruspexsystems/Ducks-in-a-Row
/// repository, so an administrator or a security reviewer who follows a type
/// from a response lands on what it means and what to do about it. The
/// release script rewrites that repository's main on every release and must
/// push nothing else; Test-ReleaseScripts.ps1 holds it to that.
///
/// The slugs are a contract with every release that emits them. A page may be
/// reworded or restyled, never renamed, and a new constant needs a new page;
/// DashboardProblemTypeTests lists the published slugs so a constant added
/// without one fails there.
///
/// Until issue #402 the base sat on the .app domain of the same name. That
/// domain was never ours, and an unrelated business registered it on
/// 2026-09-07, so every type the 0.9.0 and 0.10.0 betas emit points at a
/// stranger's site. NoLabArtefactsTests refuses the old domain anywhere in
/// what ships, which is why it is not spelled out here.
///
/// The ACME surface does not use these. It answers with the RFC 8555 section
/// 6.7 URNs in AcmeErrorType.
/// </summary>
public static class DashboardProblemType
{
    private const string Prefix = "https://ducksinarow.dev/problems/";

    public const string CaAccessDenied = Prefix + "ca-access-denied";
    public const string CaError = Prefix + "ca-error";
    public const string CaUnavailable = Prefix + "ca-unavailable";
    public const string CertificateAlreadyRevoked = Prefix + "certificate-already-revoked";
    public const string CertificateNotRevocable = Prefix + "certificate-not-revocable";
    public const string CertificateUnavailable = Prefix + "certificate-unavailable";
    public const string InvalidRevocationReason = Prefix + "invalid-revocation-reason";
    public const string RevocationBlockedByGuardrail = Prefix + "revocation-blocked-by-guardrail";
    public const string RevocationOutOfScope = Prefix + "revocation-out-of-scope";
    public const string RevocationTargetMismatch = Prefix + "revocation-target-mismatch";
}

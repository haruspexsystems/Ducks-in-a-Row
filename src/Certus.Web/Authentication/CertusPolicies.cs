namespace Certus.Web.Authentication;

/// <summary>
/// Authorization policy names and related constants for the dashboard and
/// setup APIs (issue #27, SEC-F1).
/// </summary>
public static class CertusPolicies
{
    /// <summary>
    /// Policy requiring an authenticated user in the configured admin group.
    /// Also installed as the global fallback policy, so any endpoint without
    /// explicit authorization metadata fails closed (401).
    /// </summary>
    public const string AdminOnly = "CertusAdmin";

    /// <summary>
    /// Custom request header required on state-changing /api/ requests.
    /// A cross-origin page cannot set a custom header without a CORS preflight,
    /// and Certus exposes no permissive CORS policy, so this blocks CSRF
    /// riding on ambient Windows credentials (OWASP custom request header defense).
    /// </summary>
    public const string CsrfHeaderName = "X-Certus-Csrf";
}

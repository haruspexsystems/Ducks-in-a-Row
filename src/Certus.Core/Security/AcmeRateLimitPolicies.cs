namespace Certus.Core.Security;

/// <summary>
/// The ACME rate limit policy names, shared by the registration and by the
/// [EnableRateLimiting] attributes on the controllers so the two cannot drift.
///
/// The names reach clients and operators: a refusal names its policy in the
/// problem document and in the server log, because three policies answering one
/// indistinguishable "too many requests" is what made issue #263 impossible to
/// diagnose from the outside.
/// </summary>
public static class AcmeRateLimitPolicies
{
    /// <summary>New account registration. RFC 8555 section 7.3.</summary>
    public const string NewAccount = "acme-new-account";

    /// <summary>New order submission. RFC 8555 section 7.4.</summary>
    public const string NewOrder = "acme-new-order";

    /// <summary>
    /// Authorization and order polling, both POST-as-GET reads a client repeats
    /// while it waits. Separated from <see cref="General"/> because polling is
    /// the one ACME activity whose request count is set by how long validation
    /// takes rather than by how many certificates were asked for.
    /// </summary>
    public const string Poll = "acme-poll";

    /// <summary>Everything else on the ACME surface.</summary>
    public const string General = "acme-general";

    /// <summary>
    /// A human phrase naming what the policy covers, for the problem document
    /// detail and the log line. Unknown names fall back to the general wording so
    /// a policy added later still reads sensibly.
    /// </summary>
    public static string Describe(string? policyName) => policyName switch
    {
        NewAccount => "new account requests",
        NewOrder => "new order requests",
        Poll => "authorization and order polling requests",
        _ => "requests"
    };
}

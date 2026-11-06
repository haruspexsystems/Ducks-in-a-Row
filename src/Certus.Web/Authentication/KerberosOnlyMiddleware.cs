using System.Collections.Concurrent;
using Certus.Core.Configuration;
using Certus.Web.Audit;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace Certus.Web.Authentication;

/// <summary>
/// Names the package every dashboard sign in used, and with
/// <see cref="AuthOptions.RequireKerberos"/> refuses the ones that used NTLM
/// (issue #633, CRA risk R06). Sits between authentication and authorization,
/// so it sees the identity Negotiate produced and answers before any policy
/// or endpoint runs.
///
/// <para>Why NTLM is the concern: an NTLM exchange relayed from an
/// administrator's browser to this host authenticates the relay, and the
/// anti forgery header does not stop it because the relayed request carries
/// it. Channel binding would, but Kestrel's Negotiate handler on .NET 10 has
/// no way to require or even use a channel binding token (the finding on
/// #633 and in <c>.claude/design/dashboard-auth.md</c>). Kerberos tickets
/// are bound to the service principal name of the host the browser asked
/// for, so a relayed Kerberos ticket is useless to another host, which is why
/// refusing NTLM closes the class.</para>
///
/// <para>What the package is: <c>WindowsIdentity.AuthenticationType</c>
/// reports the package the Negotiate handshake settled on, <c>Kerberos</c>
/// or <c>NTLM</c>. The refusal is a 401 with a problem document that says
/// why and no <c>WWW-Authenticate</c> challenge, because a challenge would
/// only make the browser repeat the same NTLM exchange. The sign in failure
/// counter sees that 401 (credentials offered, no challenge) and counts it,
/// so a refused NTLM sign in shows on the Audit page like any other refusal.</para>
///
/// <para>The package is logged for every identity the first time it appears
/// with that package since the service started, whether or not the option is
/// on. That line is how an operator confirms their browsers use Kerberos
/// before turning the option on, which is why it is Information and not
/// Debug. The refusal itself logs at Warning.</para>
///
/// <para>Only <c>/api</c>, like the sign in failure counter. Kestrel keeps
/// NTLM credentials for the life of the connection, so after one refused API
/// call every request on that connection carries the identity; refusing the
/// anonymous SPA shell and its assets too would leave the browser unable to
/// render the API's answer.</para>
/// </summary>
public sealed class KerberosOnlyMiddleware
{
    /// <summary>The package name a Windows identity reports for an NTLM sign in.</summary>
    public const string NtlmPackage = "NTLM";

    /// <summary>The problem title the refusal carries.</summary>
    public const string RefusalTitle = "NTLM sign in refused";

    /// <summary>
    /// Past this many identity and package pairs nothing more is remembered or
    /// logged as a first sighting. Any domain account can authenticate before
    /// the policy refuses it, so without a cap a walk over a large domain's
    /// accounts would grow the set until a restart.
    /// </summary>
    internal const int MaxTrackedSightings = 2000;

    private readonly RequestDelegate _next;
    private readonly IOptions<AuthOptions> _options;
    private readonly ILogger<KerberosOnlyMiddleware> _logger;

    // One entry per identity and package seen since start. Bounded by the
    // number of distinct administrators times two packages, so it never grows
    // past a handful of entries on a real host.
    private readonly ConcurrentDictionary<string, byte> _seen = new(StringComparer.OrdinalIgnoreCase);

    public KerberosOnlyMiddleware(
        RequestDelegate next,
        IOptions<AuthOptions> options,
        ILogger<KerberosOnlyMiddleware> logger)
    {
        _next = next;
        _options = options;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var identity = context.User.Identity;
        if (identity is not { IsAuthenticated: true } || !context.Request.Path.StartsWithSegments("/api"))
        {
            await _next(context);
            return;
        }

        var actor = AdminAuditDescription.ActorOf(context.User);
        var package = string.IsNullOrEmpty(identity.AuthenticationType) ? "(unknown)" : identity.AuthenticationType;

        if (_seen.Count < MaxTrackedSightings && _seen.TryAdd($"{actor}|{package}", 0))
        {
            _logger.LogInformation(
                "Dashboard sign in by {Actor} used {Package}", actor, package);
        }

        if (_options.Value.RequireKerberos && IsNtlm(package))
        {
            _logger.LogWarning(
                "Refused the dashboard sign in by {Actor} from {Source}: it used NTLM and Auth:RequireKerberos is on",
                actor, context.Connection.RemoteIpAddress?.ToString() ?? "unknown");
            await RefuseAsync(context);
            return;
        }

        await _next(context);
    }

    /// <summary>True for the package name an NTLM sign in reports, in any casing.</summary>
    internal static bool IsNtlm(string? package) =>
        string.Equals(package, NtlmPackage, StringComparison.OrdinalIgnoreCase);

    private static Task RefuseAsync(HttpContext context)
    {
        // No WWW-Authenticate: the browser already authenticated, with the
        // wrong package; a fresh challenge would make it do the same again.
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;

        var problem = new ProblemDetails
        {
            Status = StatusCodes.Status401Unauthorized,
            Title = RefusalTitle,
            Detail =
                "This dashboard accepts Kerberos sign ins only (Auth:RequireKerberos). Your browser " +
                "signed in with NTLM, which usually means the address you used has no HTTP service " +
                "principal name registered, or is an IP address. Use the server's registered name, " +
                "or ask the administrator to register the name; the hardening guide has the steps.",
        };
        problem.Extensions["package"] = NtlmPackage;
        return context.Response.WriteAsJsonAsync(problem, options: null, contentType: "application/problem+json");
    }
}

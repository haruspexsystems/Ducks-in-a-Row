using Certus.Core.Audit;
using Microsoft.Net.Http.Headers;

namespace Certus.Web.Audit;

/// <summary>
/// Counts failed dashboard sign ins per source address (issue #634, CRA risk
/// R07, Annex I (2)(d)). Sits in front of authentication, so it sees the
/// status the authorization middleware or the CSRF guard answered with, and
/// records only the two that mean "someone tried and was turned away":
///
/// <list type="bullet">
/// <item><description>A 401 on an <c>/api</c> route whose request carried an
/// <c>Authorization</c> header and whose challenge carries no server token.
/// A request with no header is the first leg of every Windows sign in, and a
/// challenge with a token (<c>WWW-Authenticate: Negotiate &lt;blob&gt;</c>)
/// is the middle of an NTLM handshake that is still going; neither is a
/// failure. A bare challenge after credentials were offered is.</description></item>
/// <item><description>A 403 on an <c>/api</c> route for a caller that
/// authenticated but is not in the administrator group. The CSRF guard's 403
/// is excluded: it answers an authorized administrator whose page forgot the
/// header, which is a bug to fix, not an intrusion attempt.</description></item>
/// </list>
///
/// <para>Only <c>/api</c>: the ACME surface authenticates with JWS and has its
/// own refusals. The write goes through <see cref="AdminSignInFailureRecorder"/>,
/// which never throws, so the refusal is answered whatever the database says.
/// The NTLM reading above is from the handler's documented behaviour and the
/// test scheme, not a measured handshake; see the design note.</para>
/// </summary>
public sealed class AdminSignInFailureMiddleware
{
    /// <summary>Set on <c>HttpContext.Items</c> by the CSRF guard when its 403 is the answer, so this class does not count it.</summary>
    public const string CsrfRefusedItem = "Certus.CsrfRefused";

    private readonly RequestDelegate _next;

    public AdminSignInFailureMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        await _next(context);

        if (!context.Request.Path.StartsWithSegments("/api"))
            return;

        var status = context.Response.StatusCode;
        var counts = status switch
        {
            StatusCodes.Status401Unauthorized => IsRefusedCredentials(context),
            StatusCodes.Status403Forbidden => IsAuthenticatedNonAdmin(context),
            _ => false,
        };
        if (!counts)
            return;

        // Not the request's token: a caller that drops the connection after its
        // 401 is exactly the caller to count, and the response is already sent.
        var recorder = context.RequestServices.GetRequiredService<AdminSignInFailureRecorder>();
        await recorder.RecordAsync(
            context.Connection.RemoteIpAddress?.ToString(), status, CancellationToken.None);
    }

    /// <summary>Credentials were offered and the server answered with a fresh challenge rather than a continuation.</summary>
    internal static bool IsRefusedCredentials(HttpContext context)
    {
        if (string.IsNullOrEmpty(context.Request.Headers.Authorization))
            return false;

        foreach (var challenge in context.Response.Headers[HeaderNames.WWWAuthenticate])
        {
            if (IsContinuation(challenge))
                return false;
        }

        return true;
    }

    /// <summary>
    /// "Negotiate oRQwEqADCgEBoQsGCSqGSIb3EgECAg==" is a continuation: a scheme
    /// followed by a server token. "Negotiate" alone is a refusal, and so is a
    /// list of schemes such as "Negotiate, NTLM", which has a space but no token.
    /// </summary>
    internal static bool IsContinuation(string? challenge)
    {
        if (string.IsNullOrWhiteSpace(challenge))
            return false;
        var trimmed = challenge.Trim();
        var space = trimmed.IndexOf(' ');
        if (space <= 0 || trimmed.Contains(','))
            return false;
        return trimmed[(space + 1)..].Trim().Length > 0;
    }

    /// <summary>Authenticated, refused by the policy, and not by the CSRF guard.</summary>
    internal static bool IsAuthenticatedNonAdmin(HttpContext context) =>
        context.User.Identity?.IsAuthenticated == true
        && !context.Items.ContainsKey(CsrfRefusedItem);
}

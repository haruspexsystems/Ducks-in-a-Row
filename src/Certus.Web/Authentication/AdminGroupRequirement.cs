using System.Security.Claims;
using System.Security.Principal;
using Certus.Core.Configuration;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace Certus.Web.Authentication;

/// <summary>
/// Requires membership in the configured admin group (Auth:AdminGroup),
/// defaulting to the builtin Administrators group when not configured.
/// </summary>
public sealed class AdminGroupRequirement : IAuthorizationRequirement;

/// <summary>
/// Evaluates <see cref="AdminGroupRequirement"/> against the current principal.
/// </summary>
public sealed class AdminGroupHandler : AuthorizationHandler<AdminGroupRequirement>
{
    private const string BuiltinAdministratorsSid = "S-1-5-32-544";
    private const string BuiltinAdministratorsName = @"BUILTIN\Administrators";

    private readonly AuthOptions _options;

    public AdminGroupHandler(IOptions<AuthOptions> options)
    {
        _options = options.Value;
    }

    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        AdminGroupRequirement requirement)
    {
        if (IsAdmin(context.User))
            context.Succeed(requirement);

        return Task.CompletedTask;
    }

    private bool IsAdmin(ClaimsPrincipal user)
    {
        if (user.Identity is not { IsAuthenticated: true })
            return false;

        // Production path: Negotiate yields a WindowsPrincipal whose IsInRole
        // checks the access token's groups. The SID form is the robust default
        // for builtin Administrators; a configured name covers domain groups.
        if (OperatingSystem.IsWindows() && user is WindowsPrincipal windowsPrincipal)
        {
            return string.IsNullOrEmpty(_options.AdminGroup)
                ? windowsPrincipal.IsInRole(new SecurityIdentifier(BuiltinAdministratorsSid))
                : windowsPrincipal.IsInRole(_options.AdminGroup);
        }

        // Non-Windows principals carry group membership as role claims. Only
        // test authentication schemes produce these; production registers
        // Negotiate exclusively, so no live client reaches this branch.
        // IsNullOrEmpty, not null-coalescing: a JSON null in appsettings can
        // bind as an empty string.
        return user.IsInRole(string.IsNullOrEmpty(_options.AdminGroup)
            ? BuiltinAdministratorsName
            : _options.AdminGroup);
    }
}

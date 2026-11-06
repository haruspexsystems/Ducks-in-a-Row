using System.Reflection;
using System.Text.RegularExpressions;
using Certus.Web.Audit;
using Certus.Web.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Certus.Web.Tests;

/// <summary>
/// The structural half of the audit trail (issue #634): every action an
/// administrator can reach that is not a plain read carries exactly one of
/// <see cref="AdminAuditAttribute"/> and <see cref="AdminAuditExemptAttribute"/>.
/// The filter writes a row for the first and nothing for the second, so this
/// walk is what makes "every administrator action is recorded" a fact about the
/// routing table rather than a promise about code review. A new mutating
/// endpoint fails here until its author decides which it is.
/// </summary>
[Trait("Category", "Integration")]
public class AdminAuditCoverageTests : IClassFixture<CertusWebApplicationFactory>
{
    private static readonly Regex ActionName = new("^[a-z][a-z0-9-]*(\\.[a-z][a-z0-9-]*)+$", RegexOptions.Compiled);

    private readonly CertusWebApplicationFactory _factory;

    public AdminAuditCoverageTests(CertusWebApplicationFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public void EveryMutatingAdminAction_IsAuditedOrExemptWithAReason()
    {
        var actions = MutatingAdminActions().ToList();
        actions.Should().NotBeEmpty("the admin surface has writes, so the walk found the controllers");

        var undecided = new List<string>();
        var both = new List<string>();
        foreach (var action in actions)
        {
            var audited = action.MethodInfo.GetCustomAttribute<AdminAuditAttribute>();
            var exempt = action.MethodInfo.GetCustomAttribute<AdminAuditExemptAttribute>();
            if (audited is null && exempt is null)
                undecided.Add(Describe(action));
            if (audited is not null && exempt is not null)
                both.Add(Describe(action));
        }

        undecided.Should().BeEmpty(
            "every mutating admin action needs [AdminAudit(\"...\")] or [AdminAuditExempt(\"reason\")]");
        both.Should().BeEmpty("an action is audited or exempt, never both");
    }

    [Fact]
    public void EveryAuditedAction_HasAStableDottedName_UniqueToOneRoute()
    {
        var names = MutatingAdminActions()
            .Select(a => (Action: a, Audit: a.MethodInfo.GetCustomAttribute<AdminAuditAttribute>()))
            .Where(x => x.Audit is not null)
            .ToList();

        names.Should().OnlyContain(x => ActionName.IsMatch(x.Audit!.Action),
            "action names are lower case dotted words, the shape the dashboard filters on");
        names.GroupBy(x => x.Audit!.Action).Where(g => g.Count() > 1).Select(g => g.Key)
            .Should().BeEmpty("two routes with one action name would read as one kind of change");
    }

    [Fact]
    public void EveryExemption_SaysWhy()
    {
        var reasons = MutatingAdminActions()
            .Select(a => a.MethodInfo.GetCustomAttribute<AdminAuditExemptAttribute>())
            .Where(e => e is not null)
            .Select(e => e!.Reason);

        reasons.Should().OnlyContain(r => r.Trim().Length >= 10, "a reason is a sentence, not a shrug");
    }

    [Fact]
    public void TheAuditTrailItself_HasNoWriteRoute()
    {
        var auditRoutes = MutatingAdminActions()
            .Where(a => a.ControllerTypeInfo.Name == "AuditTrailController");

        auditRoutes.Should().BeEmpty("nothing an administrator can reach may edit or delete the trail");
    }

    /// <summary>
    /// The admin surface: every action an authenticated administrator, and
    /// nobody else, can call, with any HTTP method but GET, HEAD and OPTIONS.
    /// A controller is admin only when it carries the
    /// <see cref="CertusPolicies.AdminOnly"/> policy, and also when it carries
    /// nothing, because <c>AddCertusAuth</c> installs that policy as the
    /// fallback for every endpoint without authorization metadata. Only an
    /// <c>[AllowAnonymous]</c> on the controller (the ACME protocol) or on the
    /// action (the reduced setup status) takes a route out of the walk.
    /// </summary>
    private IEnumerable<ControllerActionDescriptor> MutatingAdminActions()
    {
        var provider = _factory.Services.GetRequiredService<IActionDescriptorCollectionProvider>();
        foreach (var descriptor in provider.ActionDescriptors.Items.OfType<ControllerActionDescriptor>())
        {
            var anonymous = descriptor.ControllerTypeInfo.GetCustomAttributes<AllowAnonymousAttribute>(inherit: true).Any()
                || descriptor.MethodInfo.GetCustomAttributes<AllowAnonymousAttribute>(inherit: true).Any();
            if (anonymous)
                continue;

            var otherPolicy = descriptor.ControllerTypeInfo.GetCustomAttributes<AuthorizeAttribute>(inherit: true)
                .Concat(descriptor.MethodInfo.GetCustomAttributes<AuthorizeAttribute>(inherit: true))
                .Any(a => a.Policy is not null && a.Policy != CertusPolicies.AdminOnly);
            if (otherPolicy)
                continue; // no such controller exists today; one would need its own audit decision

            var methods = descriptor.MethodInfo.GetCustomAttributes<HttpMethodAttribute>(inherit: true)
                .SelectMany(a => a.HttpMethods)
                .ToList();
            if (methods.Count == 0 || methods.All(m => m is "GET" or "HEAD" or "OPTIONS"))
                continue;

            yield return descriptor;
        }
    }

    private static string Describe(ControllerActionDescriptor action) =>
        $"{action.ControllerTypeInfo.Name}.{action.ActionName} ({action.AttributeRouteInfo?.Template})";
}

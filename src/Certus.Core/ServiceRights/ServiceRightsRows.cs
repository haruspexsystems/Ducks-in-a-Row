namespace Certus.Core.ServiceRights;

/// <summary>How one call to the CA ended, as the check saw it.</summary>
public enum CaCallOutcome
{
    /// <summary>The CA answered.</summary>
    Answered,

    /// <summary>The CA answered and refused the service's account.</summary>
    AccessDenied,

    /// <summary>The CA could not be reached over RPC.</summary>
    Unavailable,

    /// <summary>The ADCS COM classes are missing on this server.</summary>
    ComponentsMissing,

    /// <summary>The CA answered with some other failure.</summary>
    Failed,

    /// <summary>The CA did not answer within its deadline.</summary>
    TimedOut,

    /// <summary>Not attempted, because an earlier call showed it could not work.</summary>
    NotAttempted,
}

/// <summary>One call to the CA and a plain language note about how it went.</summary>
public sealed record CaCallObservation(CaCallOutcome Outcome, string? Detail = null)
{
    public static readonly CaCallObservation NotAttempted = new(CaCallOutcome.NotAttempted);
}

/// <summary>One template the check was asked about.</summary>
/// <param name="Name">The template's programmatic name, as the CA publishes it when that is known.</param>
/// <param name="DisplayName">Its display name, or the programmatic name when unknown.</param>
/// <param name="Published">
/// Whether the CA publishes it. Null when the CA's list could not be read, which
/// is no evidence either way.
/// </param>
/// <param name="Dacl">Its permission list, or null when it was not read.</param>
/// <param name="DaclTimedOut">True when the permission list was asked for and did not arrive in time.</param>
public sealed record TemplateObservation(
    string Name,
    string DisplayName,
    bool? Published,
    TemplateDaclReading? Dacl,
    bool DaclTimedOut = false);

/// <summary>
/// A certificate this server holds that the CA issued it from a template: the
/// HTTPS certificate the wizard or the Settings page enrolled.
/// </summary>
public sealed record EnrollmentEvidence(string TemplateName, DateTimeOffset IssuedAt);

/// <summary>Everything the check saw, before it is turned into rows.</summary>
/// <param name="Components">Null when the components did not answer in time.</param>
/// <param name="Principal">Null when the account did not answer in time.</param>
/// <param name="Connect">Test Connection's reads.</param>
/// <param name="Roles">The CA's report of the service's roles. Null when not asked or not answered in time.</param>
/// <param name="View">A one row read of the certificate view the inventory sync reads.</param>
/// <param name="Templates">One observation per template asked about.</param>
/// <param name="Evidence">A certificate the CA issued to this server, when one was found.</param>
/// <param name="Simulated">True on the dev host.</param>
public sealed record ServiceRightsObservations(
    ComponentsReading? Components,
    PrincipalReading? Principal,
    CaCallObservation Connect,
    CaRolesReading? Roles,
    CaCallObservation View,
    IReadOnlyList<TemplateObservation> Templates,
    EnrollmentEvidence? Evidence,
    bool Simulated);

/// <summary>
/// Turns what the service rights check saw into rows (issue #440). Pure, so
/// every outcome is unit tested without a CA.
///
/// Three rules hold across every row. An Inferred row is never a pass.
/// Evidence of an earlier enrolment only upgrades an Inferred row to Proven; it
/// never overrides a Failed one, because a current refusal outranks an old
/// success. And a row only claims what <see cref="ServiceRightsFindings"/> says
/// was measured.
/// </summary>
public static class ServiceRightsRows
{
    private const RightNeededFor Everything =
        RightNeededFor.Issuance | RightNeededFor.Inventory | RightNeededFor.Revocation | RightNeededFor.CrlWatching;

    private const string RsatRemedy =
        "Install the ADCS Remote Administration Tools on this server " +
        "(Install-WindowsFeature RSAT-ADCS-Mgmt) and restart the service.";

    private const string RpcRemedy =
        "Check that CertSvc is running on the CA, and that TCP 135 and the dynamic RPC range " +
        "(49152 to 65535) are open from this server to the CA.";

    private const string SecurityTab = "the Certification Authority console, CA Properties, Security";

    public static IReadOnlyList<ServiceRightsRow> Build(ServiceRightsObservations observations, ServiceRightsFindings findings)
    {
        var account = observations.Principal?.AccountName ?? "this server's computer account";
        var rows = new List<ServiceRightsRow>
        {
            Domain(observations.Principal),
            Components(observations.Components),
            Connect(observations.Connect),
            RequestCertificates(observations.Connect, observations.Roles, observations.Evidence, findings, account),
            View(observations.View, observations.Connect, observations.Roles, findings, account),
            IssueAndManage(observations.Roles, observations.Connect, findings, account),
        };

        foreach (var template in observations.Templates)
            rows.Add(Template(template, observations.Principal, observations.Evidence, account));

        rows.Add(HttpsEnrolment(observations.Evidence, observations.Simulated));
        rows.Add(ChallengeEgress());
        return rows;
    }

    internal static ServiceRightsRow Domain(PrincipalReading? principal)
    {
        const string title = "Domain membership";
        if (principal is null)
            return new("domain", RightsGroup.Host, title, RightsStatus.Unproven, RightsBasis.Local, Everything,
                "The join state was not read in time.");

        return principal.DomainJoined switch
        {
            true => new("domain", RightsGroup.Host, title, RightsStatus.Proven, RightsBasis.Local, Everything,
                principal.DomainName is { } name
                    ? $"This server is joined to the {name} domain."
                    : "This server is joined to a domain."),
            false => new("domain", RightsGroup.Host, title, RightsStatus.Failed, RightsBasis.Local, Everything,
                "This server is not joined to a domain, so the CA cannot authenticate the service.",
                Remedy: "Join this server to a domain in the CA's forest, then restart the service."),
            null => new("domain", RightsGroup.Host, title, RightsStatus.Unproven, RightsBasis.Local, Everything,
                "The join state could not be read."),
        };
    }

    internal static ServiceRightsRow Components(ComponentsReading? components)
    {
        const string title = "ADCS components on this server";
        if (components is null)
            return new("components", RightsGroup.Host, title, RightsStatus.Unproven, RightsBasis.Local, Everything,
                "The ADCS components did not answer in time.");

        var missing = components.Components.Where(c => c.Outcome != ReadingOutcome.Ok).ToList();
        if (missing.Count == 0)
            return new("components", RightsGroup.Host, title, RightsStatus.Proven, RightsBasis.Local, Everything,
                "CertRequest, CertView and CertAdmin all start on this server.");

        var named = string.Join("; ", missing.Select(c => $"{c.Name}, used for {UseOf(c.Name)}"));
        var remedy = missing.Any(c => c.Outcome == ReadingOutcome.NotRegistered)
            ? RsatRemedy
            : missing[0].Detail;
        return new("components", RightsGroup.Host, title, RightsStatus.Failed, RightsBasis.Local, Everything,
            $"These ADCS components do not start on this server: {named}.", Remedy: remedy);

        static string UseOf(string component) => component switch
        {
            "CertRequest" => "every request to the CA",
            "CertView" => "the certificate inventory",
            "CertAdmin" => "revocation and the CA's report of the service's roles",
            _ => "the CA",
        };
    }

    internal static ServiceRightsRow Connect(CaCallObservation connect)
    {
        const string title = "Reaching the CA as this server";
        const RightNeededFor needed = RightNeededFor.Issuance | RightNeededFor.CrlWatching;
        return connect.Outcome switch
        {
            // What the answer proves about rights belongs to the Request
            // Certificates row, so this one says only that the path works.
            CaCallOutcome.Answered => new("ca-connect", RightsGroup.Ca, title, RightsStatus.Proven, RightsBasis.Exercised, needed,
                "The CA answered Test Connection's property reads over DCOM, as this server's account."),
            CaCallOutcome.AccessDenied => new("ca-connect", RightsGroup.Ca, title, RightsStatus.Failed, RightsBasis.Exercised, needed,
                "The CA answered and refused this server's account.",
                Remedy: connect.Detail),
            CaCallOutcome.Unavailable => new("ca-connect", RightsGroup.Ca, title, RightsStatus.Failed, RightsBasis.Exercised, needed,
                "The CA could not be reached over RPC.",
                Remedy: RpcRemedy),
            CaCallOutcome.ComponentsMissing => new("ca-connect", RightsGroup.Ca, title, RightsStatus.Failed, RightsBasis.Local, needed,
                "The ADCS COM classes are missing on this server.",
                Remedy: RsatRemedy),
            CaCallOutcome.TimedOut => new("ca-connect", RightsGroup.Ca, title, RightsStatus.Unproven, RightsBasis.NotChecked, needed,
                "The CA did not answer within 30 seconds."),
            CaCallOutcome.NotAttempted => new("ca-connect", RightsGroup.Ca, title, RightsStatus.Skipped, RightsBasis.NotChecked, needed,
                "Not attempted."),
            _ => new("ca-connect", RightsGroup.Ca, title, RightsStatus.Failed, RightsBasis.Exercised, needed,
                connect.Detail is { } detail ? $"The CA did not answer the property reads: {detail}" : "The CA did not answer the property reads."),
        };
    }

    internal static ServiceRightsRow RequestCertificates(
        CaCallObservation connect, CaRolesReading? roles, EnrollmentEvidence? evidence,
        ServiceRightsFindings findings, string account)
    {
        const string title = "Request Certificates on the CA";
        const RightNeededFor needed = RightNeededFor.Issuance | RightNeededFor.CrlWatching;
        var remedy = $"Grant {account} Request Certificates on the CA ({SecurityTab}). Authenticated Users hold it on a default CA.";

        if (findings.ConnectProvesRequestCertificates)
        {
            if (connect.Outcome == CaCallOutcome.Answered)
                return new("ca-enroll", RightsGroup.Ca, title, RightsStatus.Proven, RightsBasis.Exercised, needed,
                    "Test Connection's reads need this right, and the CA answered them.");
            if (connect.Outcome == CaCallOutcome.AccessDenied)
                return new("ca-enroll", RightsGroup.Ca, title, RightsStatus.Failed, RightsBasis.Exercised, needed,
                    "Test Connection's reads need this right, and the CA refused them.", Remedy: remedy);
        }

        if (IsBlocked(connect))
            return new("ca-enroll", RightsGroup.Ca, title, RightsStatus.Skipped, RightsBasis.NotChecked, needed,
                "The CA could not be reached, so it was not asked.");

        var row = FromRoles(roles, CaAccessRoles.Enroll, "ca-enroll", title, needed, findings, remedy, optional: false,
            heldDetail: "The CA reports this right for the service's account.",
            missingDetail: "The CA reports that the service's account does not hold this right.");

        return evidence is not null && row.Status == RightsStatus.Inferred
            ? row with
            {
                Status = RightsStatus.Proven,
                Basis = RightsBasis.PriorEnrollment,
                Detail = $"This server's HTTPS certificate was issued on {Date(evidence.IssuedAt)}, which used this right.",
            }
            : row;
    }

    internal static ServiceRightsRow View(
        CaCallObservation view, CaCallObservation connect, CaRolesReading? roles,
        ServiceRightsFindings findings, string account)
    {
        const string title = "The certificate view the inventory reads";
        const RightNeededFor needed = RightNeededFor.Inventory;

        if (IsBlocked(connect) || view.Outcome == CaCallOutcome.NotAttempted)
            return new("ca-read", RightsGroup.Ca, title, RightsStatus.Skipped, RightsBasis.NotChecked, needed,
                "The CA could not be reached, so it was not asked.");

        switch (view.Outcome)
        {
            case CaCallOutcome.Answered:
                return findings.ViewOpenProvesInventory
                    ? new("ca-read", RightsGroup.Ca, title, RightsStatus.Proven, RightsBasis.Exercised, needed,
                        "The view the inventory sync reads opened for the service's account.")
                    : new("ca-read", RightsGroup.Ca, title, RightsStatus.Inferred, RightsBasis.Exercised, needed,
                        "The view opened, but whether it shows every certificate to this account is not established.");

            case CaCallOutcome.AccessDenied:
            {
                var readHeld = roles is { Outcome: ReadingOutcome.Ok, RolesMask: { } mask } && CaAccessRoles.Has(mask, CaAccessRoles.Read);
                var detail = readHeld
                    ? "The CA refused the view although it reports Read for this account, so it may refuse remote " +
                      "administration altogether (the IF_NOREMOTEICERTADMIN interface flag)."
                    : "The CA refused the service's account the view the inventory sync reads. Request Certificates " +
                      "alone does not open it.";
                return new("ca-read", RightsGroup.Ca, title, RightsStatus.Failed, RightsBasis.Exercised, needed,
                    detail, Remedy: $"Grant {account} Read on the CA ({SecurityTab}).");
            }

            case CaCallOutcome.TimedOut:
                return new("ca-read", RightsGroup.Ca, title, RightsStatus.Unproven, RightsBasis.NotChecked, needed,
                    "The CA did not answer within 30 seconds.");

            default:
                return new("ca-read", RightsGroup.Ca, title, RightsStatus.Unproven, RightsBasis.Exercised, needed,
                    view.Detail is { } detail2 ? $"The view could not be read: {detail2}" : "The view could not be read.");
        }
    }

    internal static ServiceRightsRow IssueAndManage(
        CaRolesReading? roles, CaCallObservation connect, ServiceRightsFindings findings, string account)
    {
        const string title = "Issue and Manage Certificates on the CA";
        var needed = findings.ViewOpenProvesInventory
            ? RightNeededFor.Revocation
            : RightNeededFor.Revocation | RightNeededFor.Inventory;

        if (IsBlocked(connect))
            return new("ca-officer", RightsGroup.Ca, title, RightsStatus.Skipped, RightsBasis.NotChecked, needed,
                "The CA could not be reached, so it was not asked.", Optional: true);

        return FromRoles(roles, CaAccessRoles.Officer, "ca-officer", title, needed, findings,
            remedy: $"Grant {account} Issue and Manage Certificates on the CA ({SecurityTab}) only if Ducks in a Row " +
                    "should revoke. It also lets the account approve and deny requests, so it is a real decision.",
            optional: true,
            heldDetail: "The CA reports this right for the service's account. Only revocation uses it.",
            missingDetail: "The CA reports that the service's account does not hold this right, so revoking from the " +
                           "dashboard and through ACME revoke-cert will fail. Everything else works without it.");
    }

    internal static ServiceRightsRow Template(
        TemplateObservation template, PrincipalReading? principal, EnrollmentEvidence? evidence, string account)
    {
        var id = $"template:{template.Name}";
        var title = $"Enroll on the {template.DisplayName} template";
        const RightNeededFor needed = RightNeededFor.Issuance;
        var remedy = $"Grant Enroll on the template to {account} or to a group that holds it (the Certificate " +
                     "Templates console, the template's Properties, Security).";

        if (template.Published == false)
            return new(id, RightsGroup.Template, title, RightsStatus.Failed, RightsBasis.Local, needed,
                "The CA does not publish this template, so no request against it can succeed.",
                Remedy: "Publish it on the CA (Certificate Templates, New, Certificate Template to Issue), or choose another.",
                Template: template.Name);

        if (principal is not { Outcome: ReadingOutcome.Ok, AccountSid: { } accountSid })
            return new(id, RightsGroup.Template, title, RightsStatus.Skipped, RightsBasis.NotChecked, needed,
                "The service's account and its groups could not be read, so the template's permissions cannot be weighed.",
                Template: template.Name);

        if (template.Dacl is null)
            return new(id, RightsGroup.Template, title, RightsStatus.Unproven, RightsBasis.NotChecked, needed,
                template.DaclTimedOut ? "The directory did not answer within 20 seconds." : "The template's permissions were not read.",
                Template: template.Name);

        // NotFound included. A directory search that runs out of time comes back
        // empty, exactly like one that found nothing, and a display name the CA's
        // list could not resolve is not a cn either, so not finding the template
        // never proves it absent. A template the CA does not publish is caught
        // above, from the CA's own list.
        if (template.Dacl.Outcome != ReadingOutcome.Ok)
            return new(id, RightsGroup.Template, title, RightsStatus.Unproven, RightsBasis.ReadFromAcl, needed,
                template.Dacl.Detail ?? "The template's permissions could not be read.", Template: template.Name);

        var sids = TemplateEnrollEvaluator.SidsForNetworkLogon(accountSid, principal.GroupSids);
        var enroll = TemplateEnrollEvaluator.Evaluate(template.Dacl.Entries, sids, TemplateEnrollEvaluator.EnrollRight);
        var autoenroll = TemplateEnrollEvaluator.Evaluate(template.Dacl.Entries, sids, TemplateEnrollEvaluator.AutoenrollRight);
        var overGranted = autoenroll.Verdict == EnrollVerdict.Granted
            ? " The account also holds Autoenroll, which Ducks in a Row never uses and which can be removed."
            : "";
        var trustee = Trustee(enroll.DecidingSid, accountSid, account);

        var row = enroll.Verdict switch
        {
            EnrollVerdict.Granted => new ServiceRightsRow(id, RightsGroup.Template, title, RightsStatus.Inferred, RightsBasis.ReadFromAcl, needed,
                $"The template's permissions grant Enroll to {trustee}. The CA's policy module makes the final decision." + overGranted,
                Template: template.Name),
            EnrollVerdict.Denied => new ServiceRightsRow(id, RightsGroup.Template, title, RightsStatus.Failed, RightsBasis.ReadFromAcl, needed,
                $"A deny entry for {trustee} refuses Enroll on this template." + overGranted,
                Remedy: "Remove the deny entry, or ask whoever placed it why it is there.", Template: template.Name),
            EnrollVerdict.NotGranted => new ServiceRightsRow(id, RightsGroup.Template, title, RightsStatus.Failed, RightsBasis.ReadFromAcl, needed,
                "No entry grants Enroll to this server's account or to any group it belongs to. A group from another " +
                "domain of the forest would not be visible from here." + overGranted,
                Remedy: remedy, Template: template.Name),
            _ => new ServiceRightsRow(id, RightsGroup.Template, title, RightsStatus.Unproven, RightsBasis.ReadFromAcl, needed,
                "An entry this check cannot evaluate, such as a conditional one, decides Enroll on this template.",
                Template: template.Name),
        };

        return evidence is not null
               && row.Status == RightsStatus.Inferred
               && string.Equals(evidence.TemplateName, template.Name, StringComparison.OrdinalIgnoreCase)
            ? row with
            {
                Status = RightsStatus.Proven,
                Basis = RightsBasis.PriorEnrollment,
                Detail = $"This server's HTTPS certificate was issued from this template on {Date(evidence.IssuedAt)}.",
            }
            : row;
    }

    internal static ServiceRightsRow HttpsEnrolment(EnrollmentEvidence? evidence, bool simulated)
    {
        const string title = "A certificate issued to this server";
        const RightNeededFor needed = RightNeededFor.Issuance;

        if (simulated)
            return new("https-enrolment", RightsGroup.EndToEnd, title, RightsStatus.Skipped, RightsBasis.NotChecked, needed,
                "The demo CA issues without checking any right, so nothing it issues proves one.");

        if (evidence is not null)
            return new("https-enrolment", RightsGroup.EndToEnd, title, RightsStatus.Proven, RightsBasis.PriorEnrollment, needed,
                $"This server's HTTPS certificate was issued from the {evidence.TemplateName} template on " +
                $"{Date(evidence.IssuedAt)}. That proves Request Certificates on the CA and Enroll on that template, as of that day.");

        return new("https-enrolment", RightsGroup.EndToEnd, title, RightsStatus.Unproven, RightsBasis.NotChecked, needed,
            "No certificate this CA issued to this server was found. The HTTPS certificate on the wizard's External URL " +
            "step proves Request Certificates and Enroll on the template it uses; the wizard offers it when the URL " +
            "answers over HTTPS with a certificate this server does not trust, and the Settings page can provision one " +
            "later. Otherwise the first ACME order is the proof.");
    }

    internal static ServiceRightsRow ChallengeEgress() => new(
        "challenge-egress", RightsGroup.EndToEnd, "Reaching the hosts being validated",
        RightsStatus.Unproven, RightsBasis.NotChecked, RightNeededFor.Issuance,
        "http-01 validation reaches each host on TCP 80, tls-alpn-01 on TCP 443, and dns-01 needs a DNS server the " +
        "service can query on port 53. Which of them matter depends on your clients, so nothing here can check them " +
        "ahead of time. device-attest-01 needs none.");

    /// <summary>
    /// A row built from the CA's own report of one role. GetMyRoles answers only
    /// an account holding Read or more (measured, see
    /// <see cref="ServiceRightsFindings.MeasuredOnLab2019"/>), so a refusal says
    /// the account holds neither this role nor Read, unless the CA refuses
    /// remote administration altogether, which is why it stays Unproven.
    /// </summary>
    private static ServiceRightsRow FromRoles(
        CaRolesReading? roles, int role, string id, string title, RightNeededFor needed,
        ServiceRightsFindings findings, string? remedy, bool optional, string heldDetail, string missingDetail)
    {
        if (roles is null)
            return new(id, RightsGroup.Ca, title, RightsStatus.Unproven, RightsBasis.NotChecked, needed,
                "The CA did not report the service's roles in time.", Optional: optional);

        if (roles.Outcome == ReadingOutcome.Ok && roles.RolesMask is { } mask)
        {
            if (!findings.CaRolesTrusted)
                return new(id, RightsGroup.Ca, title, RightsStatus.Unproven, RightsBasis.ReportedByCa, needed,
                    "The CA's report of the service's roles has not been measured against its settings, so it is not relied on.",
                    Optional: optional);

            return CaAccessRoles.Has(mask, role)
                ? new(id, RightsGroup.Ca, title, RightsStatus.Inferred, RightsBasis.ReportedByCa, needed, heldDetail, Optional: optional)
                : new(id, RightsGroup.Ca, title, RightsStatus.Failed, RightsBasis.ReportedByCa, needed, missingDetail,
                    Remedy: remedy, Optional: optional);
        }

        return roles.Outcome switch
        {
            ReadingOutcome.AccessDenied => new(id, RightsGroup.Ca, title, RightsStatus.Unproven, RightsBasis.ReportedByCa, needed,
                "The CA would not report the service's roles. It reports them to an account holding Read or more, so " +
                "grant Read and check again. A CA that refuses remote administration (IF_NOREMOTEICERTADMIN) refuses " +
                "the same way.", Optional: optional),
            ReadingOutcome.NotRegistered => new(id, RightsGroup.Ca, title, RightsStatus.Unproven, RightsBasis.ReportedByCa, needed,
                roles.Detail ?? "The CertAdmin component is missing on this server.", Remedy: RsatRemedy, Optional: optional),
            _ => new(id, RightsGroup.Ca, title, RightsStatus.Unproven, RightsBasis.ReportedByCa, needed,
                roles.Detail ?? "The CA did not report the service's roles.", Optional: optional),
        };
    }

    /// <summary>A CA call outcome after which nothing else about the CA can be learned.</summary>
    private static bool IsBlocked(CaCallObservation connect) => connect.Outcome is
        CaCallOutcome.Unavailable or CaCallOutcome.ComponentsMissing or CaCallOutcome.TimedOut or CaCallOutcome.NotAttempted;

    /// <summary>Who an entry is about, in words an administrator recognises.</summary>
    internal static string Trustee(string? sid, string accountSid, string account) => sid switch
    {
        null => "no one",
        AclEntry.AnyTrustee => "an entry whose trustee could not be read",
        TemplateEnrollEvaluator.AuthenticatedUsersSid => "Authenticated Users",
        TemplateEnrollEvaluator.EveryoneSid => "Everyone",
        TemplateEnrollEvaluator.NetworkSid => "NETWORK",
        TemplateEnrollEvaluator.ThisOrganizationSid => "This Organization",
        _ when string.Equals(sid, accountSid, StringComparison.OrdinalIgnoreCase) => account,
        _ when sid.StartsWith("S-1-5-21-", StringComparison.Ordinal) && sid.EndsWith("-515", StringComparison.Ordinal) => "Domain Computers",
        _ => $"the group {sid}",
    };

    private static string Date(DateTimeOffset value) => value.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);
}

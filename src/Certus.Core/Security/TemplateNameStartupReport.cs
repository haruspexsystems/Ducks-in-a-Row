using Certus.Core.Acme.Services;
using Certus.Core.Adcs;
using Microsoft.Extensions.Logging;

namespace Certus.Core.Security;

/// <summary>
/// Says once, near boot, that a template exposed over ACME carries a character
/// in one of its published values that stops clients reaching it, or that would
/// misrepresent it on a screen.
///
/// The failure this exists for is invisible from every other angle (issue
/// #235). A certificate template's display name is free text out of Active
/// Directory, a soft hyphen is what a paste from a word processor leaves in
/// one, and issue #17 lets an ACME client address a template by that display
/// name. <c>UrlCharacterGuardMiddleware</c> then refuses the request before
/// routing, and the operator sees working clients stop against a name that
/// looks perfectly correct in the Certificate Templates console, on the
/// dashboard, and in the client's own configuration file alike.
///
/// The template OID is scanned alongside the two names (issue #292) and is the
/// one value here that stops nothing. It is reported because the setup wizard
/// prints it on every template row, so a bidirectional override in it reorders
/// the line that names the template, and because the CA is its only source: it
/// comes out of <c>CR_PROP_TEMPLATES</c> untouched and the directory does not
/// constrain it to dotted decimal.
///
/// This is deliberately not a <see cref="StartupValidator"/> check. That class
/// is a synchronous configuration matrix that does no I/O and returns a count
/// of findings, and a CA round trip inside it would put DCOM on the boot thread
/// and make its count depend on whether the CA answered. This is live state
/// read from the CA, which is the same category as the two diagnostics the
/// startup block already logs beside it.
///
/// Boot pays nothing for it. The caller runs it detached, so a CA at the end of
/// an RPC timeout costs no boot time at all, and every failure is caught and
/// demoted to Debug, so an install that has not run the wizard yet (where the
/// client throws outright) is silent rather than alarming. On a healthy install
/// the round trip is not extra work either: it fills the same five minute
/// template cache the first ACME request would have filled.
/// </summary>
public static class TemplateNameStartupReport
{
    /// <summary>
    /// Logs one warning when a template exposed over ACME carries a refused
    /// character in either of its names or in its OID, and nothing at all
    /// otherwise.
    /// </summary>
    public static async Task LogAsync(
        TemplateService templates,
        EnabledTemplatesPolicy enabledTemplates,
        ILogger logger,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var published = await templates.GetTemplatesAsync(cancellationToken);

            // Scoped to what ACME actually serves. A CA publishing forty
            // templates with one dirty legacy display name has no problem
            // unless that template is an exposed one, and warning about the
            // other thirty nine would train an operator to skip the line. The
            // wizard's template step is where a non exposed template gets
            // flagged, at the moment someone might choose it. Note that the
            // break glass Certus:Acme:ExposeAllTemplates widens this to
            // everything published, which is correct: everything published is
            // then exposed.
            var faults = published
                .Where(enabledTemplates.IsEnabled)
                .Select(TemplateNameUsability.Inspect)
                .Where(verdict => !verdict.IsClean)
                .ToList();

            if (faults.Count == 0)
            {
                logger.LogDebug(
                    "Template name check: all {Count} template(s) exposed over ACME carry a " +
                    "clean programmatic name, display name and OID",
                    published.Count(enabledTemplates.IsEnabled));
                return;
            }

            // Counted independently rather than as a remainder. Three buckets
            // that have to add up to faults.Count, and taking the last as
            // "everything else" is what made adding the OID a defect rather
            // than a member: an OID only fault would have been counted as a
            // display name fault and described as a 400 nobody is getting.
            var blocked = faults.Count(v => !v.CanEnroll);
            var displayOnly = faults.Count(v => v.CanEnroll && v.DisplayNameUnusable);
            var oidOnly = faults.Count - blocked - displayOnly;

            // The worst one, not the first one published. An operator anchors
            // on the example rather than on the counts, so naming a recoverable
            // display name fault while an unenrollable template sits in the
            // same line would point at the wrong template to go and look at.
            // Same precedence TemplateNameVerdict.First applies within one
            // verdict, applied here across them, and it is three tiers deep for
            // the same reason it is inside a verdict: an OID fault costs
            // nothing, so it is the last thing to send someone to go and look
            // at.
            var worst = faults
                .FirstOrDefault(
                    v => !v.CanEnroll,
                    faults.FirstOrDefault(v => v.DisplayNameUnusable, faults[0]))
                .First!.Value;

            logger.LogWarning(
                "{Count} certificate template(s) exposed over ACME carry a control, line " +
                "separator, or formatting character in a published value. {Blocked} carry " +
                "one in the programmatic name and cannot be enrolled at all, because the " +
                "ADCS request attribute string cannot be built from such a name. " +
                "{DisplayOnly} carry one in the display name, so a client that addresses " +
                "the template by its display name is refused with 400 before routing and " +
                "must use the programmatic name instead. {OidOnly} carry one in the " +
                "template OID alone, which refuses nothing and costs no client anything: " +
                "it is reported because the setup wizard prints the OID, where such a " +
                "character can reorder the line naming the template. The worst is " +
                "U+{CodePoint:X4} at position {Position} of a {Part}. The values are not " +
                "printed here, because printing them would write the characters these " +
                "checks exist to keep out of the log; the setup wizard's template step " +
                "names the template, and docs/troubleshooting.md has the fix",
                faults.Count,
                blocked,
                displayOnly,
                oidOnly,
                worst.Character.CodePoint,
                worst.Character.Position,
                worst.Part switch
                {
                    TemplateNamePart.Programmatic => "programmatic name",
                    TemplateNamePart.Display => "display name",
                    _ => "template OID",
                });
        }
        catch (Exception ex)
        {
            // Every reason to fail here is a reason not to say anything: no CA
            // configured yet, the CA unreachable, the wizard not run. None of
            // them is news, and none of them may take the host down.
            logger.LogDebug(ex, "Template name check skipped: the CA template list could not be read");
        }
    }
}

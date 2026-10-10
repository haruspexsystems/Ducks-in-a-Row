using Certus.Core.Security;

namespace Certus.Core.Adcs;

/// <summary>
/// Which of a published template's three values a fault sits in. The three fail
/// differently enough that a caller has to know which one it is looking at.
/// </summary>
public enum TemplateNamePart
{
    /// <summary>
    /// The programmatic name, the template's Active Directory <c>cn</c>, which
    /// is what <c>CR_PROP_TEMPLATES</c> returns and what ADCS matches a request
    /// against.
    /// </summary>
    Programmatic,

    /// <summary>
    /// The display name, the template's Active Directory <c>displayName</c>,
    /// which issue #17 also accepts as the ACME URL's template segment.
    /// </summary>
    Display,

    /// <summary>
    /// The template OID, the Active Directory <c>msPKI-Cert-Template-OID</c>,
    /// which <c>CR_PROP_TEMPLATES</c> pairs each programmatic name with.
    ///
    /// It decides nothing. It is carried for display and for resolving a
    /// certificate row's template back to a name, so a fault in it costs
    /// neither enrollment nor addressing. The member exists so the wizard and
    /// the startup log can explain a row that reads oddly (issue #292).
    /// </summary>
    Oid,
}

/// <summary>
/// One faulty value: which of the three it is, and the character that makes it
/// faulty. Carries no template text, deliberately. A verdict travels into a log
/// line, an HTTP body, and a browser, and the value that earned the verdict is
/// exactly the text none of those three may render.
/// </summary>
public readonly record struct TemplateNameFault(
    TemplateNamePart Part, DeceptiveCharacter Character)
{
    /// <summary>
    /// The noun a message puts in front of the word "character". The three
    /// spellings are the ones <see cref="AdcsRequestAttributes"/>,
    /// <see cref="AdcsCaConnectionString"/> and the ACME permanent-identifier
    /// parser already use, kept here so a fourth caller cannot invent a fourth
    /// vocabulary for the same three classes.
    /// </summary>
    public string ClassNoun => Character.Class switch
    {
        DeceptiveCharacterClass.Control => "control",
        DeceptiveCharacterClass.LineSeparator => "line separator",
        _ => "formatting",
    };
}

/// <summary>
/// Whether a template published by the CA can actually be enrolled against and
/// addressed over ACME, and whether the third value it carries can be shown as
/// published, given the characters in each.
///
/// The three fail differently, and the difference is the whole point of this
/// type. The programmatic name is what
/// <see cref="AdcsRequestAttributes.ForTemplate"/> interpolates into the request
/// attribute string, so a refused character there means no certificate can be
/// requested against the template on any path: not over ACME, not from the
/// settings page, not by the renewal service. The display name only ever
/// reaches a URL, because issue #17 lets an ACME client address a template by
/// it, so a refused character there costs that one addressing form and nothing
/// else. <c>UrlCharacterGuardMiddleware</c> refuses such a URL before routing,
/// which is issue #235: a template that resolved fine went to a hard 400 for
/// every client configured with its display name, and a soft hyphen is
/// invisible in every screen that renders the name.
///
/// The OID costs nothing at all (issue #292). Nothing routes on it and nothing
/// is built from it, so it is reported rather than acted on. It earns a scan
/// anyway because it is the value the setup wizard prints on every template
/// row, and a bidirectional override in it reorders the text around it while
/// reading as an ordinary OID everywhere an administrator would go to check.
/// The CA is its only source, and <c>msPKI-Cert-Template-OID</c> is a directory
/// string rather than a value constrained to dotted decimal, so what arrives is
/// whatever a template tool or an administrator wrote there.
///
/// This exists rather than three call sites each calling
/// <see cref="DeceptiveCharacters.Find"/> three times, because the wizard's
/// template list, the startup report, the dashboard's template endpoint and
/// their tests have to agree on which value is fatal, which is advisory, and
/// which is neither. Getting that backwards in one place would hide a template
/// that works or offer one that cannot work at all.
///
/// The type is still named for the two names it started with. Renaming it would
/// touch every call site and every test for no change in behaviour, which is a
/// worse trade than a name that undersells its third member.
///
/// It reports and never refuses, and never strips. Each caller keeps its own
/// policy on what to do about the answer, the same division
/// <see cref="DeceptiveCharacters"/> already draws: the wizard hides an
/// unenrollable template, advises about an unaddressable one and notes a
/// deceptive OID, the startup report warns, and the guard in the web host
/// refuses.
/// </summary>
public static class TemplateNameUsability
{
    /// <summary>
    /// Inspects all three values of a published template.
    /// </summary>
    public static TemplateNameVerdict Inspect(TemplateInfo template) =>
        Inspect(template.Name, template.DisplayName, template.Oid);

    /// <summary>
    /// Inspects a programmatic name, a display name, and a template OID.
    ///
    /// The OID is optional because a caller holding only the two names has
    /// nothing to say about it, and an absent value is clean by the same rule
    /// every value here follows. Production reaches this through the
    /// <see cref="TemplateInfo"/> overload, which always passes all three.
    /// </summary>
    public static TemplateNameVerdict Inspect(
        string? programmaticName, string? displayName, string? oid = null)
    {
        var programmatic = DeceptiveCharacters.Find(programmaticName);

        // A display name equal to the programmatic name is the fallback
        // AdcsClient leaves behind when the Active Directory lookup could not
        // run, not a second value an administrator chose. Scanning it again
        // would report one fault twice, so a host that is not domain joined
        // would show every dirty name as two separate problems.
        var display = string.Equals(programmaticName, displayName, StringComparison.Ordinal)
            ? null
            : DeceptiveCharacters.Find(displayName);

        // The OID gets no such dedup. AdcsClient copies the programmatic name
        // into DisplayName when the directory lookup fails; it never copies
        // anything into Oid. So a fault there that matches one in a name is a
        // genuine second occurrence, not the same one seen twice.
        var oidFault = DeceptiveCharacters.Find(oid);

        return new TemplateNameVerdict(
            programmatic is { } p
                ? new TemplateNameFault(TemplateNamePart.Programmatic, p)
                : null,
            display is { } d
                ? new TemplateNameFault(TemplateNamePart.Display, d)
                : null,
            oidFault is { } o
                ? new TemplateNameFault(TemplateNamePart.Oid, o)
                : null);
    }
}

/// <summary>
/// The answer for one template. All three faults can be set at once, so none is
/// lost when more than one value carries something.
/// </summary>
public readonly record struct TemplateNameVerdict(
    TemplateNameFault? ProgrammaticFault,
    TemplateNameFault? DisplayFault,
    TemplateNameFault? OidFault = null)
{
    /// <summary>Nothing the template carries has a refused character in it.</summary>
    public bool IsClean =>
        ProgrammaticFault is null && DisplayFault is null && OidFault is null;

    /// <summary>
    /// A certificate can be requested against this template. False is total:
    /// the request attribute string cannot be built from the name at all, so
    /// every path fails, and the setup wizard's own completion endpoint refuses
    /// to record the template.
    ///
    /// Deliberately blind to <see cref="OidFault"/>. Nothing about enrollment
    /// reads the OID, so letting one refuse a template would destroy a template
    /// that works over a value carried for display.
    /// </summary>
    public bool CanEnroll => ProgrammaticFault is null;

    /// <summary>
    /// An ACME client addressing this template by its display name is refused
    /// before routing. The programmatic name may still work; check
    /// <see cref="CanEnroll"/> for that.
    /// </summary>
    public bool DisplayNameUnusable => DisplayFault is not null;

    // There is deliberately no OidUnusable beside these two. Both of them name
    // a consequence, and a deceptive OID has none: nothing is refused, nothing
    // is hidden, and the template issues and is addressed exactly as before. A
    // property saying otherwise would be a claim a caller could act on.

    /// <summary>
    /// The fault to report when only one can be named, ordered by what it
    /// costs. The programmatic name comes first because its remediation
    /// subsumes the other two: a template renamed to fix it gets a clean
    /// display name on the way. The OID comes last because it costs nothing.
    /// </summary>
    public TemplateNameFault? First => ProgrammaticFault ?? DisplayFault ?? OidFault;
}

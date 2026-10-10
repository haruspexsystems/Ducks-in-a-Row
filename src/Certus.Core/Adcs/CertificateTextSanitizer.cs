using System.Text;
using Certus.Core.Security;

namespace Certus.Core.Adcs;

/// <summary>
/// Prepares text the certificate authority hands back for storage and display.
///
/// This lives in Certus.Core rather than inside AdcsClient so every writer that
/// can reach a SyncedCertificate column is covered by the same guard: AdcsClient
/// as it maps a CA row, the ACME subject backfills and the entity writers in
/// CertificateSyncService, and the startup pass in DatabaseInitializer. Before
/// issue #224 the sanitizer lived in Certus.Adcs, which put it out of reach of
/// the writers in this project and left them unguarded. It must stay public:
/// Certus.Core grants InternalsVisibleTo to Certus.Core.Tests only, not to
/// Certus.Adcs.
///
/// <see cref="MockAdcsClient"/> is covered indirectly rather than by calling in
/// here itself: it signs the CSR subject verbatim, and the entity writers in the
/// sync are what catch that. Sanitizing at the writer rather than only in each
/// client is what makes the guard hold for any IAdcsClient.
///
/// Every function here is idempotent, so a value may be sanitized more than once
/// on its way to the database without changing.
/// </summary>
public static class CertificateTextSanitizer
{
    /// <summary>
    /// The largest CA disposition message we keep. The CA schema allows 8192
    /// characters; real messages run well under two hundred. This matches the
    /// SubjectAlternativeNames column width and bounds both the database row
    /// and the JSON the dashboard receives.
    /// </summary>
    public const int MaxDispositionMessageLength = 2000;

    /// <summary>
    /// The widest subject we keep. The CA schema allows 8192 characters for both
    /// the request and the certificate name columns; the SyncedCertificate.Subject
    /// column stores 500 and is indexed. SQLite would not refuse an over width
    /// value, so nothing else in the chain enforces this.
    /// </summary>
    public const int MaxSubjectLength = 500;

    /// <summary>
    /// The widest template name we keep, matching the
    /// <c>SyncedCertificate.TemplateName</c> column. The CA hands back either a
    /// template OID or a programmatic name, and the AD display name that may
    /// replace it is an object name, so every legitimate value is far under this.
    /// As with the subject, SQLite would not refuse an over width value, so the
    /// bound has to be applied here or nowhere.
    /// </summary>
    public const int MaxTemplateNameLength = 200;

    /// <summary>
    /// The longest download file name we build, before the .pem or .cer
    /// extension is appended.
    ///
    /// Nothing capped this before issue #232. A Windows path component stops at
    /// 255 characters, and the percent encoding in the Content-Disposition
    /// filename* parameter triples the length of every non ASCII character, so an
    /// uncapped common name produces a download the browser cannot save. This
    /// number sits comfortably above every host name and common name seen in
    /// practice and far below the limit it protects.
    /// </summary>
    public const int MaxFileNameLength = 128;

    /// <summary>
    /// The printable characters Windows rejects in a file name. Control
    /// characters are absent on purpose; see
    /// <see cref="SanitizeFileNameComponent"/> for why.
    /// </summary>
    private const string InvalidFileNameCharacters = "\"<>|:*?\\/";

    /// <summary>
    /// The Windows reserved device names, compared case insensitively against
    /// the segment before the first dot.
    /// </summary>
    private static readonly HashSet<string> ReservedDeviceNames =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "CON", "PRN", "AUX", "NUL",
            "COM0", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
            "LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        };

    /// <summary>
    /// Prepares the CA's disposition message for storage and display.
    ///
    /// This value is authored outside Ducks and is partly influenced by whoever
    /// submitted the request: a denial frequently quotes the subject name the
    /// requester put in the CSR, so an ACME client controls a substring that
    /// ends up on an admin screen. React escapes every JSX child, so markup in
    /// the message renders as visible text, but escaping does not defend against
    /// characters that change what the admin reads; see
    /// <see cref="StripAndBound"/> for which classes go and why.
    ///
    /// Tab, carriage return, and line feed are kept here, because the CA
    /// composes multi line messages and the detail page preserves them.
    /// </summary>
    public static string? SanitizeDispositionMessage(string? raw) =>
        StripAndBound(raw, MaxDispositionMessageLength,
            keepLineBreaks: true, preserveCommonName: false);

    /// <summary>
    /// The same value as <see cref="SanitizeDispositionMessage"/>, with every run
    /// of tab, carriage return and line feed replaced by a single space, for the
    /// places the message reaches the service log (issue #362).
    ///
    /// Its sibling keeps those three on purpose, because the CA composes multi
    /// line messages and the certificate detail page renders them with
    /// whitespace-pre-line. The log has no such reader. Serilog's file sink writes
    /// the rendered message straight through, so a legitimate multi line denial
    /// already reaches the log file as several lines, and anything reading that
    /// file back sees records nobody wrote. That is an operator's problem today,
    /// and it is what would let a requester influenced substring forge a whole
    /// line if one ever carried a break: a denial frequently quotes the subject
    /// name the CSR asked for, which is the same reasoning that put the strip on
    /// this value to begin with.
    ///
    /// A substitution rather than a strip. Passing keepLineBreaks: false to
    /// <see cref="StripAndBound"/> would remove the break and fuse the words
    /// either side of it, so "Denied by Policy Module" followed by a break and
    /// "Invalid Request" would read as one run-on word. A space keeps the message
    /// readable as the one line the log wants.
    ///
    /// No second bound is needed, because collapsing a run can only shorten the
    /// value. No leading or trailing space can appear either: the sibling trims,
    /// so the first and last characters here are never breaks. Idempotent along
    /// with the rest of the class, since a flattened value has no runs left.
    /// </summary>
    public static string? SanitizeDispositionMessageForLog(string? raw)
    {
        var cleaned = SanitizeDispositionMessage(raw);
        if (cleaned == null)
            return null;

        var sb = new StringBuilder(cleaned.Length);
        var pendingBreak = false;
        foreach (var ch in cleaned)
        {
            if (ch is '\t' or '\r' or '\n')
            {
                pendingBreak = true;
                continue;
            }

            if (pendingBreak)
            {
                sb.Append(' ');
                pendingBreak = false;
            }

            sb.Append(ch);
        }

        return sb.ToString();
    }

    /// <summary>
    /// Prepares a certificate or request subject for storage and display
    /// (issues #186 and #224).
    ///
    /// Every source of this value is requester influenced, and the certificate
    /// columns are not the safe half of that pair. On a template with enrollee
    /// supplies subject the CN is whatever the CSR asked for and the CA signs it
    /// rather than rewriting it, so an issued row's name is requester authored
    /// too; the only difference from a request row is that a CA signature now
    /// stands behind it. Ducks also syncs the whole CA, so a certificate enrolled
    /// by something else entirely still reaches this dashboard.
    ///
    /// A bidirectional override makes an admin read a different hostname than
    /// the one that was issued, which HTML escaping does nothing about, and a
    /// format character in a name is not whitespace, so it survives a trim and
    /// leaves a display name no admin can type. That last one is not cosmetic:
    /// the revoke dialog confirms on a typed name match, so an unsanitized
    /// subject makes its own certificate unrevokable from the UI.
    ///
    /// Unlike the disposition message, tab and the line breaks are stripped too:
    /// the CA composes multi line explanations, but nothing legitimate puts a
    /// newline in a distinguished name, and one there forges log lines and alert
    /// email lines alike.
    ///
    /// An over long subject is cut, and the cut leads with the CN so the name
    /// survives whatever order the issuer encoded. On an issued row the full
    /// subject is still recoverable from the stored DER, which is written once
    /// and never rewritten. On a request row it is not: nothing was signed, so
    /// there is no certificate to read it back from, and the cut value is all
    /// there is.
    /// </summary>
    public static string? SanitizeSubject(string? raw) =>
        StripAndBound(raw, MaxSubjectLength,
            keepLineBreaks: false, preserveCommonName: true);

    /// <summary>
    /// Prepares a certificate template name for storage and display (issue #378).
    ///
    /// The value comes from the CA's own certificate view, and the display name
    /// that may replace it comes from a directory read, so it is authored outside
    /// Ducks exactly like the subject beside it in the same row mapper. Unlike the
    /// published template OID of issue #292, which is reported and never stripped
    /// because an operator has to compare it against the Certificate Templates
    /// console, this is display text with no such duty, so it takes the strip.
    ///
    /// It reaches more than a screen. It is persisted to
    /// <c>SyncedCertificate.TemplateName</c>, so it survives restarts; the expiry
    /// alert mail and the webhook notifier both carry it out of the process; and
    /// <c>RevocationEligibilityService</c> interpolates it into the refusal an
    /// admin reads when a certificate is out of revocation scope.
    ///
    /// <para>
    /// It is also compared, in <c>RevocationEligibilityService.TemplateInSetAsync</c>,
    /// so the strip changes a security decision and the direction is worth being
    /// explicit about. That comparison is an allow list: a name that no longer
    /// matches the configured set is refused, so a strip that breaks a match can
    /// only ever refuse a revocation, never permit one. A strip that creates a
    /// match is the other half, and it is the intended repair rather than a hole:
    /// a template named as an admin's entry plus an invisible character is the
    /// spoof itself, and leaving it unstripped is what silently makes its
    /// certificates unrevokable from the dashboard while showing the admin a name
    /// they cannot tell from the real one.
    /// </para>
    ///
    /// No common name handling: a template name is not a distinguished name, so
    /// an over long one is simply cut. Line breaks go with the rest, because
    /// nothing legitimate puts one in a template name and one there forges a line
    /// in the alert mail and the service log alike.
    ///
    /// Returns null when nothing usable is left. The column is not nullable, so
    /// every writer coalesces to the empty string, which reads downstream as the
    /// template being unknown and matches no configured set.
    /// </summary>
    public static string? SanitizeTemplateName(string? raw) =>
        StripAndBound(raw, MaxTemplateNameLength,
            keepLineBreaks: false, preserveCommonName: false);

    /// <summary>
    /// Prepares a certificate name for use as a download file name (issue #232).
    ///
    /// This is a different sink from <see cref="SanitizeSubject"/> and reached by
    /// a different path: the name comes from the stored DER at request time, never
    /// from the SyncedCertificate.Subject column, so nothing the sync sanitizes
    /// reaches it. The result becomes the Content-Disposition file name, which
    /// ASP.NET Core writes twice: filename= with everything outside printable
    /// ASCII replaced by an underscore, and filename*=UTF-8'' carrying the
    /// original percent encoded and intact. Browsers prefer the second, so a
    /// bidirectional override in a common name reaches the download bar and the
    /// file on disk, and the operator reads a hostname that is not the one they
    /// clicked.
    ///
    /// Returns null when nothing usable is left, so the caller moves on to its
    /// next candidate rather than naming the file after nothing.
    /// </summary>
    public static string? SanitizeFileNameComponent(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;

        var stripped = StripDeceptiveCharacters(raw, keepLineBreaks: false);

        // The control range needs no entry in InvalidFileNameCharacters: the
        // strip above already removed every Cc, which is what lets this rule be
        // an explicit constant instead of Path.GetInvalidFileNameChars(). That
        // API answers for the running OS, not for the file system the download
        // lands on, and on Unix it returns only the null character and the
        // forward slash, which would make almost all of this a no op. The star
        // was already spelled out separately at the old call site for the same
        // reason, since it is in the Windows set and not the Unix one.
        var sb = new StringBuilder(stripped.Length);
        foreach (var ch in stripped)
        {
            if (InvalidFileNameCharacters.IndexOf(ch) < 0)
                sb.Append(ch);
        }

        var cleaned = sb.ToString().Trim();
        if (cleaned.Length == 0)
            return null;

        // A hard cut rather than the ellipsis StripAndBound uses. The ellipsis is
        // itself non ASCII, so it would survive only as percent encoded noise in
        // the header, and a file name has no reader who needs to be told it was
        // shortened.
        if (cleaned.Length > MaxFileNameLength)
            cleaned = Cut(cleaned, MaxFileNameLength);

        return GuardReservedDeviceName(cleaned);
    }

    /// <summary>
    /// Prefixes an underscore when the name would resolve to a Windows device
    /// rather than to a file.
    ///
    /// Windows reads the device name from the segment before the first dot, so
    /// con.example.com.cer is the console exactly as CON.cer is, and that is a
    /// plausible host name rather than a contrived one. A download named for a
    /// device does not fail loudly; it disappears into the device, which is why
    /// this is worth spending a few lines on.
    ///
    /// Idempotent along with the rest of the sanitizer: the guarded form no
    /// longer matches the reserved set, so running it twice changes nothing.
    /// </summary>
    private static string GuardReservedDeviceName(string cleaned)
    {
        var dot = cleaned.IndexOf('.');
        var stem = dot < 0 ? cleaned : cleaned[..dot];

        if (!ReservedDeviceNames.Contains(stem))
            return cleaned;

        // Cut first so the underscore cannot push the result past the cap.
        if (cleaned.Length >= MaxFileNameLength)
            cleaned = Cut(cleaned, MaxFileNameLength - 1);

        return "_" + cleaned;
    }

    /// <summary>
    /// The value cut to at most <paramref name="maxLength"/>, backing off one
    /// more character when the cut would land between a surrogate pair, so the
    /// result never ends in half a character.
    ///
    /// Load bearing on both sides of the class. A stored subject must not end in
    /// half a character, and on the file name side half a surrogate pair is worse
    /// than untidy: the Content-Disposition filename* parameter is UTF-8 percent
    /// encoded, and a lone surrogate has no UTF-8 encoding at all, so it would
    /// reach the browser as a replacement character at best.
    ///
    /// A value already inside the budget is returned whole. That case is not
    /// theoretical: the CN leading branch in <see cref="StripAndBound"/> reaches
    /// <see cref="CutWithEllipsis"/> once the common name plus its separator is
    /// over the width, which the common name alone can be two characters under.
    /// Indexing before checking read one character past the end there and threw
    /// on a subject the requester authored.
    /// </summary>
    private static string Cut(string value, int maxLength)
    {
        if (value.Length <= maxLength)
            return value;

        var cut = maxLength;
        if (char.IsHighSurrogate(value[cut - 1]))
            cut--;

        return value[..cut];
    }

    /// <summary>
    /// Runs <see cref="StripDeceptiveCharacters"/> over the value, then bounds
    /// the result to the storage column.
    ///
    /// An absent, empty, or whitespace only value returns null, so the caller
    /// renders nothing at all rather than an empty labelled field.
    /// </summary>
    private static string? StripAndBound(
        string? raw, int maxLength, bool keepLineBreaks, bool preserveCommonName)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;

        var cleaned = StripDeceptiveCharacters(raw, keepLineBreaks).Trim();
        if (cleaned.Length == 0)
            return null;

        if (cleaned.Length <= maxLength)
            return cleaned;

        var tail = CutWithEllipsis(cleaned, maxLength);

        // A tail cut is the whole answer for a message, and only half of it for a
        // subject, because a subject has one part every consumer actually reads.
        //
        // The tail cut only keeps the CN when the distinguished name happens to
        // put it first, and nothing guarantees that. What does not decide it is
        // the encoding order, which is where the reasoning here was wrong from
        // issue #230 until issue #297. X509Certificate2.Subject is the reverse of
        // the encoded RDN sequence rather than a passthrough of it: RFC 4514
        // section 2.1 renders a name most specific first, and .Subject is that
        // rendering. So a name encoded general to specific (C, S, L, O, OU, CN),
        // which is the X.500 convention a certificate authority follows, displays
        // with the CN first, and a tail cut keeps it. Measured on the lab CA on
        // 2026-08-31 rather than taken from the specification: its own
        // certificate, which ADCS named, encodes DC, DC, CN and renders the
        // common name first. The old claim survived
        // because the constructor reverses on the way in as well: a subject
        // written as a string round trips unchanged, so no test that starts from
        // a string and ends at .Subject can tell the two apart, and every
        // measurement taken of it did exactly that. X500NameOrderingTests pins
        // the mechanism against the raw DER instead.
        //
        // The branch stays, on the grounds that actually hold. The value here is
        // frequently not .Subject at all: AdcsClient prefers the certificate
        // authority's own DistinguishedName and CommonName columns and only falls
        // back to the parsed certificate when all four of those are blank, and
        // the columns are a different renderer. Measured on the lab CA on
        // 2026-08-31, that renderer agrees with .Subject and leads with the
        // common name, so this branch is defensive rather than necessary against
        // a healthy CA. Both halves are live paths rather than one being the
        // exception, which the lab CA shows plainly (2026-08-31, 57 issued rows):
        // an ACME request carries no subject, so its columns are EMPTY and the
        // parsed certificate is what the sanitizer sees, while the rows this
        // product's own TLS enrollment left carry a column. Ducks also syncs the
        // whole CA, so a certificate some other tool enrolled arrives here too.
        // And a multi valued relative distinguished name (OU=IT+CN=leaf) puts
        // text ahead of the common name inside a single component. Leading with
        // the CN makes the result independent of all of that, which is the one
        // sentence of the original comment that survived the correction.
        if (!preserveCommonName || tail.Contains("CN=", StringComparison.OrdinalIgnoreCase))
            return tail;

        var commonName = CommonNameRdn(cleaned);
        if (commonName == null)
            return tail;

        // The trailing comma is deliberate: the CN extraction on every consumer
        // ends the name at the next comma that is neither quoted nor escaped, so
        // this keeps the ellipsis out of the name itself rather than making it
        // read as part of the hostname.
        var led = commonName + ", …";
        return led.Length <= maxLength ? led : CutWithEllipsis(commonName, maxLength);
    }

    /// <summary>
    /// Removes the character classes that survive HTML escaping and still change
    /// what an admin reads, leaving the trim and the bound to the caller.
    ///
    /// The classes are <see cref="DeceptiveCharacters"/>, shared with the guards
    /// that refuse rather than strip. Control characters (Unicode Cc) forge log
    /// lines and drive terminal escape sequences. Line separators (U+2028 and
    /// U+2029, Unicode Zl and Zp) forge a line for any reader that honours them,
    /// which is most things that are not a .NET line reader (issue #234). Format
    /// characters (Unicode Cf) include the bidirectional overrides U+202A to
    /// U+202E and the isolates U+2066 to U+2069, which reverse how a name renders
    /// without altering a single byte of markup, and the tag block U+E0020 to
    /// U+E007F, which hides text outright. Nothing a CA writes, and nothing a
    /// well formed DN contains, needs any of them.
    ///
    /// <paramref name="keepLineBreaks"/> keeps tab, carriage return and line feed
    /// so a genuinely multi line disposition message survives to be displayed. It
    /// deliberately does not extend to U+2028 and U+2029: a CA that means a line
    /// break writes one, and the whole reason those two are stripped is that a
    /// reader cannot agree with the writer about whether they are one.
    /// </summary>
    private static string StripDeceptiveCharacters(string raw, bool keepLineBreaks)
    {
        var sb = new StringBuilder(raw.Length);
        for (var i = 0; i < raw.Length; i++)
        {
            var ch = raw[i];

            if (keepLineBreaks && ch is '\t' or '\r' or '\n')
            {
                sb.Append(ch);
                continue;
            }

            // Classify reads the category from the string rather than the char,
            // so a format character above the BMP is stripped too. Those arrive
            // as a surrogate pair, and the category of a lone surrogate is
            // Surrogate and never Format, so a per char lookup misses the whole
            // class, including the tag block U+E0020 to U+E007F that encodes
            // arbitrary ASCII invisibly. Both halves have to go together here, or
            // what is left behind is invalid UTF-16 (issue #228). A high
            // surrogate with no low surrogate after it reads as Surrogate and is
            // kept, exactly as before.
            if (DeceptiveCharacters.Classify(raw, i) != DeceptiveCharacterClass.None)
            {
                if (char.IsHighSurrogate(ch) && i + 1 < raw.Length && char.IsLowSurrogate(raw[i + 1]))
                    i++;
                continue;
            }

            sb.Append(ch);
        }

        return sb.ToString();
    }

    /// <summary>
    /// The value cut to fit exactly, with the ellipsis counted inside the width.
    /// The surrogate pair handling is <see cref="Cut"/>'s; one character of the
    /// budget is spent on the ellipsis before it is asked.
    /// </summary>
    private static string CutWithEllipsis(string value, int maxLength) =>
        Cut(value, maxLength - 1) + "…";

    /// <summary>
    /// The first CN relative distinguished name, "CN=" and all, or null.
    ///
    /// Delegates to <see cref="DistinguishedNameParser"/>, which is the one place
    /// that knows where a common name ends. Until issue #231 this split on the
    /// first comma, as the extraction in DashboardMetricsService and the frontend
    /// both did, and all three misread a common name carrying a quoted comma.
    ///
    /// The parser returns the component in its original spelling, quoting and
    /// all, which is what the lead below needs: the value it emits has to parse
    /// back to the same name, and an unescaped one would not.
    /// </summary>
    private static string? CommonNameRdn(string subject) =>
        DistinguishedNameParser.CommonNameRdn(subject);
}

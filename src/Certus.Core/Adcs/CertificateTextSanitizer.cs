using System.Globalization;
using System.Text;

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
    /// Strips the character classes that survive HTML escaping and still change
    /// what an admin reads, then bounds the result to the storage column.
    ///
    /// Control characters (Unicode Cc) forge log lines and drive terminal escape
    /// sequences. Format characters (Unicode Cf) include the bidirectional
    /// overrides U+202A to U+202E and the isolates U+2066 to U+2069, which
    /// reverse how a name renders without altering a single byte of markup, and
    /// the tag block U+E0020 to U+E007F, which hides text outright. Nothing a CA
    /// writes, and nothing a well formed DN contains, needs any of them.
    ///
    /// An absent, empty, or whitespace only value returns null, so the caller
    /// renders nothing at all rather than an empty labelled field.
    /// </summary>
    private static string? StripAndBound(
        string? raw, int maxLength, bool keepLineBreaks, bool preserveCommonName)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;

        var sb = new StringBuilder(Math.Min(raw.Length, maxLength));
        for (var i = 0; i < raw.Length; i++)
        {
            var ch = raw[i];

            if (keepLineBreaks && ch is '\t' or '\r' or '\n')
            {
                sb.Append(ch);
                continue;
            }

            // Read the category from the string rather than the char, so a
            // format character above the BMP is stripped too. Those arrive as a
            // surrogate pair, and the category of a lone surrogate is Surrogate
            // and never Format, so a per char lookup misses the whole class,
            // including the tag block U+E0020 to U+E007F that encodes arbitrary
            // ASCII invisibly. Both halves have to go together, or what is left
            // behind is invalid UTF-16 (issue #228). A high surrogate with no
            // low surrogate after it reads as Surrogate and is kept, exactly as
            // before.
            if (char.IsControl(ch) ||
                CharUnicodeInfo.GetUnicodeCategory(raw, i) == UnicodeCategory.Format)
            {
                if (char.IsHighSurrogate(ch) && i + 1 < raw.Length && char.IsLowSurrogate(raw[i + 1]))
                    i++;
                continue;
            }

            sb.Append(ch);
        }

        var cleaned = sb.ToString().Trim();
        if (cleaned.Length == 0)
            return null;

        if (cleaned.Length <= maxLength)
            return cleaned;

        var tail = CutWithEllipsis(cleaned, maxLength);

        // A tail cut is the whole answer for a message, and only half of it for a
        // subject, because a subject has one part every consumer actually reads.
        //
        // The tail cut only keeps the CN when the distinguished name happens to
        // put it first, and nothing guarantees that. X509Certificate2.Subject is a
        // straight passthrough of the encoded RDN sequence: it does not reorder,
        // which was measured on net10.0 rather than assumed. ADCS conventionally
        // encodes general to specific (C, S, L, O, OU, CN), which puts the CN
        // last, exactly where a tail cut destroys it. Leading with the CN instead
        // makes the result independent of how the issuer ordered the name, so no
        // measurement of any particular CA's column ordering is load bearing.
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
    /// The value cut to fit exactly, with the ellipsis counted inside the width.
    /// Backs off one more character when the cut would land between a surrogate
    /// pair, so the stored value never ends in half a character.
    /// </summary>
    private static string CutWithEllipsis(string value, int maxLength)
    {
        var cut = maxLength - 1;
        if (char.IsHighSurrogate(value[cut - 1]))
            cut--;

        return value[..cut] + "…";
    }

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

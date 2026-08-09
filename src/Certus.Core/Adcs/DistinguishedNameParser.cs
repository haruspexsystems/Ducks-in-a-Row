using System.Text;

namespace Certus.Core.Adcs;

/// <summary>
/// Reads the common name out of a stored subject string, honouring the escaping
/// the encoders actually use (issue #231).
///
/// A comma is legal inside a common name value, and neither encoder that feeds
/// this codebase drops it. Windows CertNameToStr wraps the whole value in double
/// quotes and doubles any quote already inside it; the RFC 4514 form puts a
/// backslash in front of it instead. Reading up to the first comma therefore
/// returns a fragment of the name rather than the name. On a template with
/// enrollee supplies subject the common name is whatever the certificate signing
/// request asked for, so a requester decides when that happens.
///
/// This parses the string rather than the encoded name, which is deliberate.
/// X500DistinguishedName.EnumerateRelativeDistinguishedNames is the correct
/// reader for a DER encoded name, but every caller here holds
/// SyncedCertificate.Subject, which is a display string and frequently not a
/// valid distinguished name at all: AdcsClient stores the certificate authority's
/// bare CommonName column with no "CN=" prefix, or the first subject alternative
/// name for a SAN only certificate, and CertificateTextSanitizer stores the
/// truncation form "CN=host.example.com, …". Re-encoding any of those through
/// new X500DistinguishedName(string) throws. The mirror of this grammar in
/// src/frontend/src/types/index.ts cannot reach the managed API either, so a
/// grammar both sides can implement is what keeps all four readers agreeing on
/// one answer.
///
/// Both entry points return null when the subject carries no common name. Each
/// caller keeps its own fallback rather than sharing one, because the three
/// differ on purpose: the activity feed shows the whole subject, the lineage key
/// uses the trimmed subject, and the sanitizer gives up on leading with the name.
/// </summary>
internal static class DistinguishedNameParser
{
    /// <summary>
    /// The first common name value, unquoted and unescaped, or null when the
    /// subject carries none. This is the name a reader displays or keys a
    /// lineage on.
    /// </summary>
    internal static string? CommonName(string? subject) => FindCommonName(subject)?.Value;

    /// <summary>
    /// The first common name component exactly as it was spelled, "CN=" prefix
    /// and escaping intact, or null when the subject carries none.
    ///
    /// The original spelling is load bearing rather than incidental.
    /// CertificateTextSanitizer re-emits this slice into a truncated subject that
    /// then has to parse back to the same name, so handing it the unescaped value
    /// would turn a quoted comma into a real separator and break that round trip.
    ///
    /// On a multi-valued relative distinguished name ("CN=a+OU=b") this returns
    /// the common name component alone rather than the whole name. The caller
    /// only needs something that parses back to the same common name, and the
    /// shorter slice does that.
    /// </summary>
    internal static string? CommonNameRdn(string? subject) => FindCommonName(subject)?.Text;

    /// <summary>The raw slice of a component paired with its decoded value.</summary>
    private readonly record struct Component(string Text, string Value);

    /// <summary>
    /// Walks the subject one component at a time and returns the first common
    /// name that carries a value, or null.
    ///
    /// The first that carries a value, not simply the first: a component spelled
    /// "CN=" with nothing after it is skipped so a real common name later in the
    /// same subject is still found. Both readers this replaces behaved that way,
    /// one through its regular expression requiring a character and the other
    /// through an explicit length test.
    /// </summary>
    private static Component? FindCommonName(string? subject)
    {
        if (string.IsNullOrWhiteSpace(subject))
            return null;

        var position = 0;
        while (position < subject.Length)
        {
            var end = FindComponentEnd(subject, position);
            var text = subject[position..end].Trim();
            position = end + 1;

            if (text.Length == 0)
                continue;

            // A component with no equals sign is not an attribute at all. The
            // sanitizer's truncation marker "…" arrives that way, and so does a
            // bare name the certificate authority handed back with no "CN="
            // prefix. Both have to be skipped rather than misread as a value.
            var equals = FindValueStart(text);
            if (equals < 0)
                continue;

            if (!text.AsSpan(0, equals).Trim().Equals("CN", StringComparison.OrdinalIgnoreCase))
                continue;

            var value = Unescape(text[(equals + 1)..]);
            if (string.IsNullOrWhiteSpace(value))
                continue;

            return new Component(text, value);
        }

        return null;
    }

    /// <summary>
    /// The index one past the end of the component starting at
    /// <paramref name="start"/>: the next separator that is neither quoted nor
    /// escaped, or the end of the subject.
    ///
    /// Comma and semicolon both separate relative distinguished names in the
    /// X.500 string form. Plus separates the parts of a multi-valued one, and is
    /// treated the same way here because a common name sitting after one is
    /// still a common name.
    /// </summary>
    private static int FindComponentEnd(string subject, int start)
    {
        var quoted = false;
        for (var i = start; i < subject.Length; i++)
        {
            var ch = subject[i];

            // A backslash escapes only outside quotes, and only in front of a
            // character RFC 4514 lets it escape. Inside a quoted value it is an
            // ordinary character, because the quoting form has no need of it: the
            // only thing that is special in there is the doubled quote.
            //
            // The IsEscapable test has to match the one in Unescape or the two
            // disagree about where a component ends, which is worse than either
            // rule alone. A backslash in front of anything else is literal, which
            // is the only thing it can be in a name CertNameToStr rendered.
            if (ch == '\\' && !quoted && i + 1 < subject.Length && IsEscapable(subject[i + 1]))
            {
                // The escaped character is literal, so it can never be a
                // separator and the scan steps over both.
                i++;
                continue;
            }

            if (ch == '"')
            {
                // A doubled quote inside a quoted value is one literal quote and
                // does not close it. That is how CertNameToStr writes a quote
                // that was part of the name.
                if (quoted && i + 1 < subject.Length && subject[i + 1] == '"')
                {
                    i++;
                    continue;
                }

                quoted = !quoted;
                continue;
            }

            if (!quoted && ch is ',' or ';' or '+')
                return i;
        }

        return subject.Length;
    }

    /// <summary>
    /// The index of the equals sign separating the attribute type from its value,
    /// or -1 when the component carries none. Quote and escape aware for the same
    /// reason the boundary scan is: an equals sign inside a value is part of the
    /// name, and a subject built to be misread is exactly where one shows up.
    /// </summary>
    private static int FindValueStart(string component)
    {
        var quoted = false;
        for (var i = 0; i < component.Length; i++)
        {
            var ch = component[i];

            if (ch == '\\' && !quoted && i + 1 < component.Length && IsEscapable(component[i + 1]))
            {
                i++;
                continue;
            }

            if (ch == '"')
            {
                if (quoted && i + 1 < component.Length && component[i + 1] == '"')
                {
                    i++;
                    continue;
                }

                quoted = !quoted;
                continue;
            }

            if (!quoted && ch == '=')
                return i;
        }

        return -1;
    }

    /// <summary>
    /// The decoded value: surrounding quotes removed, doubled quotes collapsed to
    /// one, and backslash escapes resolved.
    ///
    /// The value is trimmed before decoding and not after, so whatever a quoted
    /// value chose to keep survives. Quoting is how CertNameToStr preserves a
    /// leading or trailing space in a name, and trimming afterwards would undo
    /// exactly the thing the quotes were written for.
    /// </summary>
    private static string Unescape(string raw)
    {
        var value = raw.Trim();
        if (value.Length == 0)
            return string.Empty;

        var sb = new StringBuilder(value.Length);
        var quoted = false;

        for (var i = 0; i < value.Length; i++)
        {
            var ch = value[i];

            if (ch == '\\' && !quoted && i + 1 < value.Length && IsEscapable(value[i + 1]))
            {
                sb.Append(value[i + 1]);
                i++;
                continue;
            }

            if (ch == '"')
            {
                if (quoted && i + 1 < value.Length && value[i + 1] == '"')
                {
                    sb.Append('"');
                    i++;
                    continue;
                }

                quoted = !quoted;
                continue;
            }

            sb.Append(ch);
        }

        return sb.ToString();
    }

    /// <summary>
    /// Whether a backslash in front of this character is an escape rather than
    /// two literal characters. RFC 4514 section 3 lists exactly these.
    ///
    /// The restriction is load bearing, and the reason is that only one of the two
    /// encoders escapes at all. CertNameToStr quotes instead, and it does not
    /// treat a backslash as special in either direction: a name holding one is
    /// rendered with the backslash intact and no quotes around it, because a
    /// backslash is not on its list of characters worth quoting for. So in the
    /// Windows form every backslash is literal, and a reader that resolves the
    /// character after it unconditionally rewrites names that were never escaped:
    /// "CORP\svc" came back as "CORPsvc", with the backslash simply gone.
    ///
    /// Hex escapes are not decoded at all, which this predicate enforces by
    /// leaving the digits out. RFC 4514 does define the "\hh" byte form, but no
    /// encoder that reaches this parser emits it: CertNameToStr has no escaping
    /// form whatsoever, and the RFC 4514 renderer in BouncyCastle escapes the
    /// special characters with a plain backslash. Decoding it therefore served no
    /// real input and forged names out of ones the certificate did carry, since a
    /// requester may put the literal text "\74\72\75\73\74\65\64" in a common name
    /// and Windows stores it verbatim. Read as hex it spells "trusted".
    ///
    /// It also mangled any ordinary name whose backslash happened to be followed
    /// by two hex digits, which "CORP\ab-server" is. That decoded to the single
    /// byte 0xAB, and a lone byte above 0x7F is not valid UTF-8 on its own, so the
    /// name came back as "CORP", the replacement character, then "-server".
    /// </summary>
    private static bool IsEscapable(char ch) =>
        ch is ',' or '+' or '"' or '\\' or '<' or '>' or ';' or '=' or '#' or ' ';
}

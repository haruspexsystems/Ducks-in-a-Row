using System.Text;

namespace Certus.Core.Adcs;

/// <summary>
/// Reads the common name out of a stored subject string, honouring the quoting
/// the encoder actually uses (issue #231).
///
/// A comma is legal inside a common name value, and the encoder does not drop
/// it: Windows CertNameToStr wraps the whole value in double quotes and doubles
/// any quote already inside it. Reading up to the first comma therefore returns
/// a fragment of the name rather than the name. On a template with enrollee
/// supplies subject the common name is whatever the certificate signing request
/// asked for, so a requester decides when that happens.
///
/// Quoting is the only escaping form this grammar knows, and that is a
/// deliberate narrowing rather than an omission (issue #296). CertNameToStr has
/// no backslash escape in either direction: a value holding a backslash is
/// rendered with it intact and no quotes around it, because a backslash is not
/// on its list of characters worth quoting for. So every backslash that reaches
/// this parser is literal, and it is written back out literal.
///
/// The parser used to read the RFC 4514 backslash dialect alongside the Windows
/// one, because MockAdcsClient rendered subjects through BouncyCastle. PR #293
/// moved the mock onto X509Certificate2 like every other producer, which left
/// one dialect and made the narrowing safe. Reading both was not merely
/// redundant, it was wrong, and in three escalating ways that are worth keeping
/// on the record because each one was a security finding:
///
/// - Decoding the RFC 4514 "\hh" byte form forged names outright (issue #238). A
///   requester may put the literal text "\74\72\75\73\74\65\64" in a common name
///   and Windows stores it verbatim; read as hex it spells "trusted".
/// - Resolving the character after a backslash unconditionally rewrote names
///   that were never escaped, so "CORP\svc" came back as "CORPsvc" with the
///   backslash simply gone, and "CORP\ab-server" decoded to a lone 0xAB byte
///   that is not valid UTF-8 alone and landed as a replacement character.
/// - Treating a backslash in front of a separator as an escape swallowed the
///   component boundary whenever a value ended in one (issue #296). Measured off
///   a real certificate, "CN=CORP\, O=Example" read back as "CORP, O=Example",
///   and with a component ahead of the common name, "O=CORP\,
///   CN=leaf.example.com" read back as no common name at all. That second shape
///   was called the ordinary ADCS ordering here until issue #297 corrected the
///   premise: the string rendering reverses the encoding, so a name encoded
///   general to specific renders common name first (X500NameOrderingTests). It
///   is reachable all the same, because the callers usually hold the certificate
///   authority's own column rather than a managed rendering, and because a multi
///   valued relative distinguished name puts text ahead of the common name
///   inside one component whatever the order.
///
/// A quoted value is unaffected by any of this. CertNameToStr writes
/// CN="evil, O=Trusted Corp" for a name carrying a separator, and the quote and
/// doubled quote handling below reads it exactly as it always did.
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
    /// The first common name value, with its quoting decoded, or null when the
    /// subject carries none. This is the name a reader displays or keys a
    /// lineage on.
    /// </summary>
    internal static string? CommonName(string? subject) => FindCommonName(subject)?.Value;

    /// <summary>
    /// The first common name component exactly as it was spelled, "CN=" prefix
    /// and quoting intact, or null when the subject carries none.
    ///
    /// The original spelling is load bearing rather than incidental.
    /// CertificateTextSanitizer re-emits this slice into a truncated subject that
    /// then has to parse back to the same name, so handing it the decoded value
    /// would turn a quoted comma into a real separator and break that round trip.
    /// That round trip is also what carries a value ending in a backslash safely
    /// through the sanitizer: the slice keeps the backslash, the sanitizer puts a
    /// separator after it, and the second pass no longer reads the pair as one
    /// (issue #296).
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

            var value = DecodeValue(text[(equals + 1)..]);
            if (string.IsNullOrWhiteSpace(value))
                continue;

            return new Component(text, value);
        }

        return null;
    }

    /// <summary>
    /// The index one past the end of the component starting at
    /// <paramref name="start"/>: the next separator that is not quoted, or the
    /// end of the subject.
    ///
    /// Comma and semicolon both separate relative distinguished names in the
    /// X.500 string form. Plus separates the parts of a multi-valued one, and is
    /// treated the same way here because a common name sitting after one is
    /// still a common name.
    ///
    /// A backslash is not consulted, which is what makes a value ending in one
    /// safe (issue #296). The class summary has the measurement; the short of it
    /// is that a backslash in front of a separator is two characters, the last
    /// of the value and the start of the next component, and stepping over the
    /// pair merged them.
    /// </summary>
    private static int FindComponentEnd(string subject, int start)
    {
        var quoted = false;
        for (var i = start; i < subject.Length; i++)
        {
            var ch = subject[i];

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
    /// or -1 when the component carries none. Quote aware for the same reason the
    /// boundary scan is: an equals sign inside a value is part of the name, and a
    /// subject built to be misread is exactly where one shows up.
    /// </summary>
    private static int FindValueStart(string component)
    {
        var quoted = false;
        for (var i = 0; i < component.Length; i++)
        {
            var ch = component[i];

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
    /// The decoded value: surrounding quotes removed and doubled quotes collapsed
    /// to one. A backslash is copied through untouched, because CertNameToStr
    /// never wrote one as an escape.
    ///
    /// The value is trimmed before decoding and not after, so whatever a quoted
    /// value chose to keep survives. Quoting is how CertNameToStr preserves a
    /// leading or trailing space in a name, and trimming afterwards would undo
    /// exactly the thing the quotes were written for.
    /// </summary>
    private static string DecodeValue(string raw)
    {
        var value = raw.Trim();
        if (value.Length == 0)
            return string.Empty;

        var sb = new StringBuilder(value.Length);
        var quoted = false;

        for (var i = 0; i < value.Length; i++)
        {
            var ch = value[i];

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
}

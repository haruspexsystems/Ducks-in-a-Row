using Certus.Core.Security;

namespace Certus.Core.Adcs;

/// <summary>
/// Validates the CA connection string, the "config string" that names the
/// certificate authority in the form <c>host\CA name</c>.
///
/// This is the sibling of <see cref="AdcsRequestAttributes"/> for the other
/// administrator supplied string that reaches ADCS, and it is deliberately a
/// separate guard because the failure mode is different. The connection string
/// is its own <c>ICertRequest::Submit</c> parameter and is never concatenated
/// into the request attribute string, so it cannot smuggle an attribute and
/// CVE-2026-54121 does not reach the CA through it. What it can do is corrupt
/// the record: the string is written verbatim into the service log on ordinary
/// operations (AdcsClient logs it on every CA info read, template query, chain
/// read, submission and revocation), and that log is what an operator reads to
/// reconstruct what happened. A carriage return or line feed forges log lines,
/// and a bidirectional override makes the CA identity render as a different
/// host wherever it is echoed (issue #220).
///
/// Presence is not this guard's business. A missing value is valid here because
/// a mock CA install has none and a partly filled wizard draft has none yet;
/// the endpoints that genuinely require one keep their own check. That is the
/// one place this differs from the template guard, where a name is always
/// required.
/// </summary>
public static class AdcsCaConnectionString
{
    /// <summary>
    /// A generous ceiling on the recorded string. The real one is about 318
    /// characters: a DNS host name tops out at 253, the separator is one, and a
    /// CA common name tops out at 64. Nothing legitimate comes close to this
    /// limit, and without it an oversized value floods every log line the
    /// connection string appears on, which is the same audit integrity problem
    /// as a forged line by another route.
    /// </summary>
    public const int MaxLength = 512;

    /// <summary>
    /// Whether a CA connection string is safe to record and to write to the
    /// log. Null, empty, or whitespace passes: see the note on presence above.
    ///
    /// Three character categories are refused, matching
    /// <see cref="AdcsRequestAttributes.TryValidateTemplateName"/> and scanned by
    /// the same <see cref="DeceptiveCharacters"/>. Control characters, all of
    /// them rather than only carriage return and line feed, because the C0
    /// range, DEL, and the C1 range all have a claim on being treated as a line
    /// break by something that reads the log. Line separators (U+2028 and
    /// U+2029, categories Zl and Zp), which have the same claim and which every
    /// guard in the product passed until issue #234. And Unicode format
    /// characters (category Cf), which include the bidirectional overrides
    /// U+202A to U+202E, the isolates U+2066 to U+2069, and the tag block
    /// U+E0020 to U+E007F, because the connection string is shown on the wizard
    /// and the settings screens and an embedded right to left override makes one
    /// CA read as another while a tag sequence hides text entirely. This is the
    /// call <see cref="CertificateTextSanitizer.SanitizeDispositionMessage"/>
    /// already makes for CA authored text reaching the same surfaces, tab and the
    /// two line break characters excepted: a CA legitimately composes a multi line
    /// message and the detail page renders one, so that function keeps those three
    /// and
    /// <see cref="CertificateTextSanitizer.SanitizeDispositionMessageForLog"/>
    /// flattens them for the log instead. A CA address needs none of them.
    ///
    /// Values are refused, never stripped. A connection string is an address,
    /// so quietly rewriting one would point the service at a CA nobody asked
    /// for.
    ///
    /// <paramref name="error"/> reports the position and code point rather than
    /// echoing the value, so a rejected string cannot carry those characters
    /// onward into the log line or the HTTP response body that reports the
    /// refusal.
    /// </summary>
    public static bool TryValidate(string? caConnectionString, out string? error)
    {
        if (string.IsNullOrWhiteSpace(caConnectionString))
        {
            error = null;
            return true;
        }

        if (caConnectionString.Length > MaxLength)
        {
            error =
                $"The CA connection string is {caConnectionString.Length} characters, " +
                $"longer than the {MaxLength} character limit. Use the CA's connection " +
                $"string in the form host\\CA name.";
            return false;
        }

        if (DeceptiveCharacters.Find(caConnectionString) is { } found)
        {
            error = found.Class switch
            {
                DeceptiveCharacterClass.Control =>
                    $"The CA connection string contains a control character " +
                    $"(U+{found.CodePoint:X4}) at position {found.Position}. A line break there would forge " +
                    $"entries in the service log, which is the record of what the CA " +
                    $"was asked to do. Use the CA's connection string in the form " +
                    $"host\\CA name.",

                DeceptiveCharacterClass.LineSeparator =>
                    $"The CA connection string contains a line separator character " +
                    $"(U+{found.CodePoint:X4}) at position {found.Position}. Some log readers treat it as " +
                    $"a line break, so it would forge entries in the service log wherever " +
                    $"the log is read by one of them. Use the CA's connection string in " +
                    $"the form host\\CA name.",

                _ =>
                    $"The CA connection string contains a formatting character " +
                    $"(U+{found.CodePoint:X4}) at position {found.Position}. Those characters can make the CA " +
                    $"display as a different host. Use the CA's connection string in " +
                    $"the form host\\CA name.",
            };
            return false;
        }

        error = null;
        return true;
    }
}

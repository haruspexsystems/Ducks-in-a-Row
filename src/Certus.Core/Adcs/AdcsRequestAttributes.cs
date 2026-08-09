using System.Globalization;

namespace Certus.Core.Adcs;

/// <summary>
/// Builds the request attribute string handed to <c>ICertRequest::Submit</c>.
///
/// ADCS takes request attributes as one string of <c>Name:Value</c> pairs
/// separated by newlines, so any value interpolated into that string is a place
/// where a caller could append attributes it never meant to send. That matters
/// because some ADCS attributes change how the CA builds the certificate:
/// CVE-2026-54121 ("CertiGhost") abuses <c>cdc</c> and <c>rmd</c> to point the
/// CA's identity lookup at an attacker controlled host and get a domain
/// controller certificate back.
///
/// Ducks in a Row sends exactly one attribute, the certificate template, and
/// this type is the only place that string is built. Construction and
/// validation live together so the boundary is local: a future caller cannot
/// pass unresolved input without going through the guard, and no caller has to
/// remember an invariant that lives somewhere else (issue #175).
/// </summary>
public static class AdcsRequestAttributes
{
    /// <summary>The attribute ADCS matches a request against a template with.</summary>
    private const string TemplateAttribute = "CertificateTemplate";

    /// <summary>
    /// The attribute string for a template enrollment. Throws
    /// <see cref="ArgumentException"/> when the name is missing, or when it
    /// carries a character that could smuggle a second attribute or disguise
    /// how the name reads. Call <see cref="TryValidateTemplateName"/> instead at
    /// an API boundary, where the answer should be a 400 rather than
    /// an exception.
    /// </summary>
    public static string ForTemplate(string templateName)
    {
        if (!TryValidateTemplateName(templateName, out var error))
            throw new ArgumentException(error, nameof(templateName));

        return $"{TemplateAttribute}:{templateName}";
    }

    /// <summary>
    /// Whether a template name is safe to interpolate into the attribute string
    /// and to record. Two categories are refused.
    ///
    /// Control characters, all of them rather than only carriage return and
    /// line feed. ADCS is documented as separating pairs with a newline but not
    /// as to which other characters its parser honours, so the guard covers the
    /// C0 range, DEL, and the C1 range rather than betting on the parser.
    ///
    /// Unicode format characters (category Cf), which include the bidirectional
    /// overrides U+202A to U+202E, the isolates U+2066 to U+2069, and the tag
    /// block U+E0020 to U+E007F. These cannot smuggle an attribute, but a
    /// template name is written to the log and shown on the wizard and settings
    /// screens, where an embedded right to left override makes a name render as
    /// a different name entirely and a tag sequence hides text outright. This
    /// matches the call
    /// <see cref="CertificateTextSanitizer.SanitizeDispositionMessage"/> already
    /// makes for CA authored text. No template name needs a format character.
    ///
    /// Names are refused, never stripped. A name that needs sanitizing did not
    /// come from the CA's published template list, and quietly rewriting it
    /// would submit a request for a template nobody asked for.
    ///
    /// <paramref name="error"/> reports the position and code point rather than
    /// echoing the name, so a rejected value cannot carry those characters
    /// onward into a log line or an HTTP response body.
    /// </summary>
    public static bool TryValidateTemplateName(string? templateName, out string? error)
    {
        if (string.IsNullOrWhiteSpace(templateName))
        {
            error = "A certificate template name is required.";
            return false;
        }

        for (var i = 0; i < templateName.Length; i++)
        {
            var c = templateName[i];

            if (char.IsControl(c))
            {
                error =
                    $"The certificate template name contains a control character " +
                    $"(U+{(int)c:X4}) at position {i}. ADCS separates request " +
                    $"attributes with newlines, so a name like that could add " +
                    $"attributes to the request. Use a template name the CA publishes.";
                return false;
            }

            // Read the category from the string rather than the char, so a
            // format character above the BMP is caught. Those arrive as a
            // surrogate pair, and the category of a lone surrogate is Surrogate
            // and never Format, so a per char lookup misses the whole class.
            // The tag block U+E0020 to U+E007F is the one that matters: it
            // encodes arbitrary ASCII invisibly, so a name could carry hidden
            // text through every screen that shows it. The string overload
            // resolves the pair; at the trailing half it answers Surrogate,
            // which is correct because the pair was already judged at its
            // leading half (issue #228).
            if (CharUnicodeInfo.GetUnicodeCategory(templateName, i) == UnicodeCategory.Format)
            {
                var codePoint = char.IsHighSurrogate(c)
                    ? char.ConvertToUtf32(templateName, i)
                    : c;

                error =
                    $"The certificate template name contains a formatting character " +
                    $"(U+{codePoint:X4}) at position {i}. Those characters can make the " +
                    $"name display as a different name. Use a template name the CA " +
                    $"publishes.";
                return false;
            }
        }

        error = null;
        return true;
    }
}

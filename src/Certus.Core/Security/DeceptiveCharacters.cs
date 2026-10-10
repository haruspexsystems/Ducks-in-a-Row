using System.Globalization;

namespace Certus.Core.Security;

/// <summary>
/// Which class of deceptive character a scanned position falls into. The three
/// named classes do different damage and earn different wording in a refusal,
/// which is why this is not a boolean.
/// </summary>
public enum DeceptiveCharacterClass
{
    /// <summary>Nothing to refuse at this position.</summary>
    None = 0,

    /// <summary>
    /// Unicode Cc: the C0 range, DEL, and the C1 range. These forge a line
    /// outright, and inside an ADCS request attribute string a line feed adds
    /// an attribute the caller never sent.
    /// </summary>
    Control,

    /// <summary>
    /// Unicode Zl and Zp: U+2028 LINE SEPARATOR and U+2029 PARAGRAPH SEPARATOR.
    /// These forge a line only for a reader that honours them, which .NET's own
    /// <c>TextReader.ReadLine</c> does not; see the note on
    /// <see cref="DeceptiveCharacters"/> for who does.
    /// </summary>
    LineSeparator,

    /// <summary>
    /// Unicode Cf: the bidirectional overrides U+202A to U+202E, the isolates
    /// U+2066 to U+2069, the zero width space, the soft hyphen, and the tag
    /// block U+E0020 to U+E007F. These cannot forge a line. They disguise one.
    /// </summary>
    Format,
}

/// <summary>
/// One deceptive character: which class it belongs to, where it sat, and the
/// code point an operator can look up. Never the character itself, and never
/// the value it came from, so a refusal cannot carry the payload onward.
/// </summary>
/// <param name="Class">The class matched. Never <see cref="DeceptiveCharacterClass.None"/>.</param>
/// <param name="Position">The UTF-16 index the character started at.</param>
/// <param name="CodePoint">The whole rune, never a surrogate half.</param>
public readonly record struct DeceptiveCharacter(
    DeceptiveCharacterClass Class, int Position, int CodePoint);

/// <summary>
/// The one place that answers "may this character appear in a value that reaches
/// the service log or an admin screen".
///
/// Several guards across the product ask that question: the template name and CA
/// connection string builders in <c>Certus.Core.Adcs</c>, the URL path guard in
/// <c>Certus.Web</c>, the ACME permanent-identifier parser, and the strip that
/// <c>CertificateTextSanitizer</c> runs over CA authored text. Each keeps its own
/// policy on presence, length, and wording, and each answers a refusal in its own
/// voice. Only the character question is shared, and it is shared because it kept
/// being copied.
///
/// That copying has now cost two multi site fixes. Issue #228 found that reading
/// the category from a <c>char</c> misses every format character above the BMP,
/// because those arrive as a surrogate pair whose halves each read as Surrogate;
/// PR #229 corrected the scanners one by one. Issue #234 found that U+2028 and
/// U+2029 are category Zl and Zp, so neither <c>char.IsControl</c> nor a Format
/// test sees them, and every guard in the product passed both. A third such class
/// would have cost a third sweep. This type is what makes the next one a one line
/// change.
///
/// On Zl and Zp specifically: .NET's <c>TextReader.ReadLine</c>, and grep and
/// less alike, break on carriage return and line feed only, so the service log
/// reads back with the line count it was written with. Other readers disagree.
/// UAX #14 makes both mandatory breaks, Python's <c>str.splitlines</c> honours
/// them, and so does anything that ships the file to a SIEM with its own
/// splitter. Refusing them costs nothing, because no template name, CA address,
/// URL path, or device serial needs a line break of any spelling.
///
/// The three classes together close that question completely. Every code point
/// any mainstream splitter treats as a line break is Cc, Zl, or Zp: the set
/// Python breaks on is U+000A, U+000B, U+000C, U+000D, U+001C, U+001D, U+001E,
/// U+0085, U+2028, and U+2029, and the first eight are all Cc. There is no
/// eleventh character to find later.
/// </summary>
public static class DeceptiveCharacters
{
    /// <summary>
    /// The class of the character starting at <paramref name="index"/>.
    ///
    /// The category is read from the string rather than from the <c>char</c>,
    /// which is the whole of the issue #228 fix. A format character above the
    /// BMP arrives as a surrogate pair, and the category of a lone surrogate is
    /// Surrogate and never Format, so a per char lookup misses the entire class,
    /// including the tag block U+E0020 to U+E007F that encodes arbitrary ASCII
    /// invisibly. The string overload resolves the pair at its leading half and
    /// answers Surrogate at the trailing half, which is right: the pair was
    /// already judged one index earlier.
    ///
    /// The control half was never affected either way, because every control
    /// character is inside the BMP.
    /// </summary>
    public static DeceptiveCharacterClass Classify(string value, int index) =>
        CharUnicodeInfo.GetUnicodeCategory(value, index) switch
        {
            UnicodeCategory.Control => DeceptiveCharacterClass.Control,
            UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator
                => DeceptiveCharacterClass.LineSeparator,
            UnicodeCategory.Format => DeceptiveCharacterClass.Format,
            _ => DeceptiveCharacterClass.None,
        };

    /// <summary>
    /// The first deceptive character in <paramref name="value"/>, or null when
    /// there is none. A null or empty value has none.
    ///
    /// Callers that refuse a value want this. <see cref="Classify"/> is for the
    /// one caller that walks every position because it strips rather than
    /// refuses.
    /// </summary>
    public static DeceptiveCharacter? Find(string? value)
    {
        if (string.IsNullOrEmpty(value))
            return null;

        for (var i = 0; i < value.Length; i++)
        {
            var matched = Classify(value, i);
            if (matched == DeceptiveCharacterClass.None)
                continue;

            return new DeceptiveCharacter(matched, i, CodePointAt(value, i));
        }

        return null;
    }

    /// <summary>
    /// The whole rune starting at <paramref name="index"/>, so a report names a
    /// character an operator can look up rather than a surrogate half like
    /// U+DB40, which does not exist on its own.
    ///
    /// The pair is re-checked rather than assumed. A high surrogate only ever
    /// classifies as Format when a low surrogate follows it, so by the time this
    /// is reached the pair is already known good, but <c>ConvertToUtf32</c>
    /// throws on a broken pair and this runs on hostile input.
    /// </summary>
    private static int CodePointAt(string value, int index)
    {
        var c = value[index];

        return char.IsHighSurrogate(c)
            && index + 1 < value.Length
            && char.IsLowSurrogate(value[index + 1])
                ? char.ConvertToUtf32(value, index)
                : c;
    }
}

using System.Diagnostics.CodeAnalysis;

namespace Certus.Core.Acme.Models;

/// <summary>
/// A parsed ACME permanent-identifier value, grammar
/// <c>device-identifier-value ["/" assigner-OID]</c>
/// (draft-ietf-acme-device-attest-08 section 3). The raw string is the unit
/// of protocol comparison, always octet for octet; the parts exist for
/// policy and display. The split is on the FIRST "/", so nothing after it
/// can smuggle a second value part.
/// </summary>
public sealed class PermanentIdentifierValue
{
    /// <summary>
    /// Maximum accepted raw length. Matches the authorization and allowlist
    /// identifier columns, so an accepted value always fits storage.
    /// </summary>
    public const int MaxLength = 253;

    /// <summary>The device identifier part (before any "/").</summary>
    public string Value { get; }

    /// <summary>The assigner OID part in dotted form, or null when absent.</summary>
    public string? AssignerOid { get; }

    /// <summary>The full raw string as received; the unit of comparison.</summary>
    public string Raw { get; }

    private PermanentIdentifierValue(string value, string? assignerOid, string raw)
    {
        Value = value;
        AssignerOid = assignerOid;
        Raw = raw;
    }

    /// <summary>
    /// Parses and validates a permanent-identifier value. Rejects empty
    /// values, oversize values, control characters, leading or trailing
    /// whitespace, an empty device identifier part, and a malformed assigner
    /// OID. Inner spaces are allowed: the draft does not restrict the value
    /// alphabet and asset style identifiers may contain them.
    /// </summary>
    public static bool TryParse(
        string? raw,
        [NotNullWhen(true)] out PermanentIdentifierValue? parsed,
        [NotNullWhen(false)] out string? error)
    {
        parsed = null;

        if (string.IsNullOrEmpty(raw))
        {
            error = "The permanent-identifier value is empty.";
            return false;
        }

        if (raw.Length > MaxLength)
        {
            error = $"The permanent-identifier value exceeds {MaxLength} characters.";
            return false;
        }

        foreach (var c in raw)
        {
            if (char.IsControl(c))
            {
                error = "The permanent-identifier value contains control characters.";
                return false;
            }
        }

        if (char.IsWhiteSpace(raw[0]) || char.IsWhiteSpace(raw[^1]))
        {
            error = "The permanent-identifier value has leading or trailing whitespace.";
            return false;
        }

        var slash = raw.IndexOf('/');
        var value = slash < 0 ? raw : raw[..slash];
        var assigner = slash < 0 ? null : raw[(slash + 1)..];

        if (value.Length == 0)
        {
            error = "The permanent-identifier value has an empty device identifier part.";
            return false;
        }

        if (assigner != null && !IsValidDottedOid(assigner))
        {
            error = "The permanent-identifier assigner is not a valid dotted OID.";
            return false;
        }

        parsed = new PermanentIdentifierValue(value, assigner, raw);
        error = null;
        return true;
    }

    /// <summary>
    /// Octet for octet comparison of the raw value, per the draft's
    /// identifier comparison rule. No case folding, no normalization.
    /// </summary>
    public bool OctetMatches(string? other) =>
        string.Equals(Raw, other, StringComparison.Ordinal);

    /// <summary>
    /// Validates a dotted OID: at least two arcs, digits only, no empty arc,
    /// no leading zero, root arc 0 to 2, and a second arc under 40 when the
    /// root arc is 0 or 1 (the ITU-T X.660 encoding rule).
    /// </summary>
    private static bool IsValidDottedOid(string oid)
    {
        var arcs = oid.Split('.');
        if (arcs.Length < 2)
            return false;

        foreach (var arc in arcs)
        {
            if (arc.Length == 0)
                return false;
            foreach (var c in arc)
            {
                if (c is < '0' or > '9')
                    return false;
            }
            if (arc.Length > 1 && arc[0] == '0')
                return false;
        }

        if (arcs[0] is not ("0" or "1" or "2"))
            return false;
        if (arcs[0] != "2" && (arcs[1].Length > 2 || int.Parse(arcs[1]) > 39))
            return false;

        return true;
    }
}

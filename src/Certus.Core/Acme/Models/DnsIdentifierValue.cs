using System.Diagnostics.CodeAnalysis;
using System.Net;
using Certus.Core.Security;

namespace Certus.Core.Acme.Models;

/// <summary>
/// Why a dns identifier was refused. Two kinds, because RFC 8555 section 6.7
/// draws the same line the device path already draws: a value the grammar
/// cannot read is <c>malformed</c>, and a value that reads perfectly well but
/// names something this server will not issue for is
/// <c>rejectedIdentifier</c>. An IP address is the second kind: "192.168.2.1"
/// is valid letter-digit-hyphen text and only policy refuses it.
/// </summary>
public enum DnsIdentifierRefusalKind
{
    /// <summary>The value is not a host name. Maps to <c>malformed</c>.</summary>
    Malformed,

    /// <summary>The value is an IP address. Maps to <c>rejectedIdentifier</c>.</summary>
    IpLiteral,
}

/// <summary>
/// One refusal: which kind it is, and the sentence a client is told. The
/// detail never carries the value itself, so a refusal cannot walk the
/// client's payload back out through a problem document, a log line, or the
/// dashboard that renders them.
/// </summary>
/// <param name="Kind">Which ACME error the caller should answer with.</param>
/// <param name="Detail">Plain language reason, free of the offending value.</param>
public readonly record struct DnsIdentifierRefusal(
    DnsIdentifierRefusalKind Kind, string Detail);

/// <summary>
/// A parsed ACME <c>dns</c> identifier value: a host name, optionally carrying
/// the single leading <c>*.</c> that marks a wildcard (RFC 8555 section 7.1.3).
///
/// Until issue #345 there was no grammar here at all. new-order took any
/// non-empty string that was not <c>localhost</c> or a blocked IP literal, so
/// IP addresses, URL forms, path fragments and shell metacharacters all became
/// authorizations, and the value reached the http-01 validator's fetch URL
/// verbatim. The egress guard vets the address it eventually connects to, but
/// that is one fence at the far end of the path; this is the fence at the near
/// end, where nothing has been created yet.
///
/// The alphabet is letter-digit-hyphen plus underscore. Strict RFC 1123 would
/// drop the underscore, but Windows DNS accepts it, ADCS issues for names that
/// carry it, and an internal certificate authority that cannot name its own
/// hosts is worse than one that accepts a name the public web would not.
/// <see cref="Services.AllowedDomainsPolicy.ValidateEntry"/> already accepts an
/// underscore in an administrator's allowed domain entry, so the two surfaces
/// agree: every name an administrator can allow is a name an order can ask for.
///
/// Refusals never echo the value, matching
/// <see cref="PermanentIdentifierValue"/> and the other guards.
/// </summary>
public sealed class DnsIdentifierValue
{
    /// <summary>
    /// Maximum accepted length of the whole value, wildcard marker included.
    /// Matches the authorization identifier column, so an accepted value
    /// always fits storage.
    ///
    /// The marker is inside the limit, not outside it, because the stored
    /// value keeps it: <c>OrderService.CreateOrderAsync</c> writes
    /// <c>identifier.Value</c> verbatim into
    /// <c>AcmeAuthorization.IdentifierValue</c>, which is declared
    /// <c>HasMaxLength(253)</c>. Measuring the stripped name instead would let
    /// a wildcard through at 255 characters and quietly break that promise on
    /// any provider that enforces a declared length. The cost is that a
    /// wildcard base name is capped at 251, which no real name approaches.
    /// </summary>
    public const int MaxLength = 253;

    /// <summary>Maximum length of one label, per RFC 1035 section 2.3.4.</summary>
    public const int MaxLabelLength = 63;

    private const string WildcardPrefix = "*.";

    /// <summary>The full raw string as received, wildcard marker included.</summary>
    public string Raw { get; }

    /// <summary>
    /// The host name with any wildcard marker stripped. This is the value to
    /// screen, resolve, or match a policy entry against; <see cref="Raw"/> is
    /// the value to store and compare.
    /// </summary>
    public string Name { get; }

    /// <summary>Whether the raw value carried the leading <c>*.</c>.</summary>
    public bool IsWildcard { get; }

    private DnsIdentifierValue(string raw, string name, bool isWildcard)
    {
        Raw = raw;
        Name = name;
        IsWildcard = isWildcard;
    }

    /// <summary>
    /// Parses and validates a dns identifier value.
    ///
    /// The check order is load bearing, because it decides which reason a
    /// value is given rather than merely whether it is refused:
    ///
    /// The deceptive character scan runs ahead of the ASCII rule, so a
    /// bidirectional override or a tag block character is named for what it is
    /// instead of reported as "some non ASCII character". It is the same
    /// <see cref="DeceptiveCharacters"/> scan the device path runs, for the
    /// same reason (issues #228 and #234).
    ///
    /// The IP address probe runs ahead of the label grammar, because an IPv4
    /// literal passes the label grammar: digits and dots are ordinary
    /// letter-digit-hyphen text. Probing first is also what gives every IP
    /// form one disposition. Left to the grammar, "192.168.2.1" would be
    /// refused as policy and "::1" as a syntax error, which is an accident of
    /// two alphabets rather than a decision anyone made.
    ///
    /// A trailing dot earns its own sentence rather than falling into the
    /// empty label rule. "example.com." is a legal DNS presentation form, so a
    /// client that sends it has done something reasonable; but finalize
    /// compares CSR subject alternative names to order identifiers normalizing
    /// only case and surrounding whitespace, so the order would be accepted
    /// here and then always fail with badCSR. Refusing it now, with the reason,
    /// is the only answer that does not either strand the client or silently
    /// rewrite the name it asked for.
    /// </summary>
    public static bool TryParse(
        string? raw,
        [NotNullWhen(true)] out DnsIdentifierValue? parsed,
        [NotNullWhen(false)] out DnsIdentifierRefusal? refusal)
    {
        parsed = null;

        if (string.IsNullOrWhiteSpace(raw))
        {
            // The wording new-order has always used for an absent value.
            refusal = Malformed("Identifier value must not be empty.");
            return false;
        }

        if (DeceptiveCharacters.Find(raw) is { } found)
        {
            var kind = found.Class switch
            {
                DeceptiveCharacterClass.Control => "control",
                DeceptiveCharacterClass.LineSeparator => "line separator",
                _ => "formatting",
            };

            refusal = Malformed(
                $"The identifier value contains a {kind} character " +
                $"(U+{found.CodePoint:X4}) at position {found.Position}.");
            return false;
        }

        var isWildcard = raw.StartsWith(WildcardPrefix, StringComparison.Ordinal);
        var name = isWildcard ? raw[WildcardPrefix.Length..] : raw;

        // One wildcard, at the front, and it must name something. "*",
        // "*.*.example.com", "**.example.com" and "web*.example.com" all land
        // here rather than in the label rules, so the client is told what the
        // marker is for instead of being told an asterisk is a bad character.
        if (name.Length == 0 || name.Contains('*', StringComparison.Ordinal))
        {
            refusal = Malformed(
                "A wildcard identifier must be a single leading '*.' followed by a domain name.");
            return false;
        }

        // Measured on the raw value, marker included, because the raw value is
        // what gets stored.
        if (raw.Length > MaxLength)
        {
            refusal = Malformed($"The identifier value exceeds {MaxLength} characters.");
            return false;
        }

        if (IsIpAddress(name))
        {
            refusal = new DnsIdentifierRefusal(
                DnsIdentifierRefusalKind.IpLiteral,
                "The identifier value is an IP address. " +
                "Order a certificate for a host name, not for an address.");
            return false;
        }

        if (name.EndsWith('.'))
        {
            refusal = Malformed(
                "The identifier value ends in a dot. Send the name without it, " +
                "exactly as it will appear in the certificate request.");
            return false;
        }

        if (ValidateLabels(name) is { } labelRefusal)
        {
            refusal = labelRefusal;
            return false;
        }

        parsed = new DnsIdentifierValue(raw, name, isWildcard);
        refusal = null;
        return true;
    }

    /// <summary>
    /// Walks the labels, refusing an empty one, an oversize one, a character
    /// outside the alphabet, and a leading or trailing hyphen. Returns null
    /// when every label is good.
    /// </summary>
    private static DnsIdentifierRefusal? ValidateLabels(string name)
    {
        var labelStart = 0;

        for (var i = 0; i <= name.Length; i++)
        {
            if (i < name.Length && name[i] != '.')
            {
                var c = name[i];
                if (c > 0x7F)
                {
                    return Malformed(
                        $"The identifier value contains a non ASCII character at position {i}. " +
                        "Send an internationalized name in its punycode A label form.");
                }

                if (!IsLabelCharacter(c))
                {
                    return Malformed(
                        "The identifier value contains a character that is not allowed in a " +
                        $"host name at position {i}.");
                }

                continue;
            }

            var length = i - labelStart;
            if (length == 0)
            {
                return Malformed(
                    "The identifier value has an empty label. A domain name cannot start with " +
                    "a dot or contain two dots in a row.");
            }

            if (length > MaxLabelLength)
            {
                return Malformed(
                    $"The identifier value has a label longer than {MaxLabelLength} characters.");
            }

            if (name[labelStart] == '-' || name[i - 1] == '-')
            {
                return Malformed(
                    "The identifier value has a label that starts or ends with a hyphen.");
            }

            labelStart = i + 1;
        }

        return null;
    }

    /// <summary>
    /// Letter, digit, hyphen, and underscore. ASCII only; the caller has
    /// already refused anything above U+007F with its own reason.
    /// </summary>
    private static bool IsLabelCharacter(char c) =>
        c is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9') or '-' or '_';

    /// <summary>
    /// Whether the name is an IP address in any form a client might send.
    ///
    /// A bracket pair is unwrapped first, so the IPv6 URL authority form
    /// "[::1]" is recognized as the address it is rather than falling through
    /// to the grammar and being refused for its brackets. Mirrors the same
    /// unwrap in <see cref="Services.AllowedDomainsPolicy.ValidateEntry"/>.
    ///
    /// One trailing dot is dropped for the same reason, so "127.0.0.1." is
    /// answered as the address it plainly is rather than as a trailing dot on
    /// an otherwise fine name. The trailing dot rule below still owns
    /// "example.com.", which is a real name a client can fix by resending.
    ///
    /// <c>IPAddress.TryParse</c> reads every shorthand IPv4 form, so "10.1",
    /// "167772161" and "0x0a000001" are all caught here rather than passing
    /// the label rules as ordinary text and then being expanded to 10.0.0.1 by
    /// the resolver at validation time. The same breadth means a single label
    /// all-digit name such as "2026" reads as a packed address and is refused.
    /// That is intended rather than an accident: RFC 1123 section 2.1
    /// discourages an all-numeric top label for exactly this ambiguity, and the
    /// Windows resolver does treat "2026" as an address, so a certificate for
    /// it would name something no resolver ever answers for. Pinned by test.
    /// </summary>
    private static bool IsIpAddress(string name)
    {
        var bare = name.Length > 1 && name[0] == '[' && name[^1] == ']'
            ? name[1..^1]
            : name;

        if (bare.EndsWith('.'))
            bare = bare[..^1];

        return IPAddress.TryParse(bare, out _);
    }

    private static DnsIdentifierRefusal Malformed(string detail) =>
        new(DnsIdentifierRefusalKind.Malformed, detail);
}

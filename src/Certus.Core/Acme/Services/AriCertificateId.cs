using System.Security.Cryptography.X509Certificates;
using Certus.Core.Acme.Crypto;

namespace Certus.Core.Acme.Services;

/// <summary>
/// The ARI certificate identifier (RFC 9773 §4.1): base64url of the
/// keyIdentifier octets from the certificate's Authority Key Identifier
/// extension, a period, base64url of the serial number's DER content octets
/// (sign pad byte kept, tag and length stripped), with all trailing '='
/// stripped from both halves.
///
/// This class is the single home for that grammar. Parsing is strict where
/// <see cref="JwsService.Base64UrlDecode"/> is deliberately permissive: the
/// RFC forbids padding and the standard alphabet, so the alphabet is checked
/// here before delegating, and the JWS helper stays tolerant for its own
/// callers.
/// </summary>
public static class AriCertificateId
{
    /// <summary>
    /// Generous ceiling on the identifier as a whole. An AKI keyIdentifier is
    /// typically 20 octets (27 base64url chars) and a serial at most 20 octets
    /// plus a pad byte, so real identifiers sit far below this; the cap exists
    /// so an anonymous caller cannot make the decoder chew on arbitrary input.
    /// </summary>
    private const int MaxLength = 256;

    /// <summary>
    /// Parses an ARI certificate identifier into its two octet halves.
    /// Returns false for anything that is not strict RFC 9773 §4.1 syntax.
    /// </summary>
    public static bool TryParse(string? value, out byte[] keyIdentifier, out byte[] serialNumber)
    {
        keyIdentifier = [];
        serialNumber = [];

        if (string.IsNullOrEmpty(value) || value.Length > MaxLength)
            return false;

        var dot = value.IndexOf('.');
        if (dot <= 0 || dot != value.LastIndexOf('.') || dot == value.Length - 1)
            return false;

        var keyIdPart = value[..dot];
        var serialPart = value[(dot + 1)..];
        if (!IsStrictBase64Url(keyIdPart) || !IsStrictBase64Url(serialPart))
            return false;

        keyIdentifier = JwsService.Base64UrlDecode(keyIdPart);
        serialNumber = JwsService.Base64UrlDecode(serialPart);
        return keyIdentifier.Length > 0 && serialNumber.Length > 0;
    }

    /// <summary>Formats the two octet halves as an ARI certificate identifier.</summary>
    public static string Format(byte[] keyIdentifier, byte[] serialNumber)
    {
        return JwsService.Base64UrlEncode(keyIdentifier) + "." +
               JwsService.Base64UrlEncode(serialNumber);
    }

    /// <summary>
    /// Reads the certificate's own identifier halves. False when the
    /// certificate carries no Authority Key Identifier keyIdentifier: such a
    /// certificate cannot be addressed by ARI at all, because the client
    /// builds the identifier from the same extension. Callers that verify a
    /// requested identifier compare these octets, never the formatted string:
    /// base64 decoding tolerates non canonical trailing bits, so two distinct
    /// strings can name the same octets.
    /// </summary>
    public static bool TryFromCertificate(
        X509Certificate2 certificate, out byte[] keyIdentifier, out byte[] serialNumber)
    {
        keyIdentifier = [];
        serialNumber = [];

        foreach (var extension in certificate.Extensions)
        {
            if (extension.Oid?.Value != "2.5.29.35")
                continue;

            try
            {
                var aki = new X509AuthorityKeyIdentifierExtension();
                aki.CopyFrom(extension);
                if (aki.KeyIdentifier is not { } akiKeyId || akiKeyId.Length == 0)
                    return false;

                keyIdentifier = akiKeyId.ToArray();
                serialNumber = certificate.SerialNumberBytes.ToArray();
                return true;
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                return false;
            }
        }

        return false;
    }

    /// <summary>
    /// Formats the certificate's own ARI identifier, or null when
    /// <see cref="TryFromCertificate"/> cannot read one.
    /// </summary>
    public static string? FromCertificate(X509Certificate2 certificate)
    {
        return TryFromCertificate(certificate, out var keyIdentifier, out var serialNumber)
            ? Format(keyIdentifier, serialNumber)
            : null;
    }

    /// <summary>
    /// The serial half in the form <see cref="Data.Entities.AcmeCertificate.SerialNumber"/>
    /// stores: uppercase hex of the DER content octets, exactly what
    /// <see cref="X509Certificate2.SerialNumber"/> returns for the same bytes.
    /// </summary>
    public static string SerialHex(byte[] serialNumber)
    {
        return Convert.ToHexString(serialNumber);
    }

    private static bool IsStrictBase64Url(string value)
    {
        // A length of 4n + 1 is impossible for base64 of any byte count, so
        // refusing it here is what makes the decode below infallible.
        if (value.Length % 4 == 1)
            return false;

        foreach (var c in value)
        {
            var ok = c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_';
            if (!ok)
                return false;
        }

        return true;
    }
}

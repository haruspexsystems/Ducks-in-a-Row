namespace Certus.Core.Adcs;

/// <summary>
/// Bridges the two representations a certificate serial number arrives in:
/// the CA database stores lowercase hex with no pad, while
/// X509Certificate2.SerialNumber is uppercase hex and can carry a leading 00
/// pad byte when the DER integer's top bit is set. Comparisons across the
/// two must normalize both sides. The ACME revoke path is untouched by this:
/// it stores and compares the X509 form on both sides, so exact equality is
/// correct there.
/// </summary>
public static class SerialNumbers
{
    /// <summary>Canonical form for cross representation matching.</summary>
    public static string Normalize(string serial) =>
        serial.TrimStart('0').ToUpperInvariant();

    /// <summary>Equality across the CA database and X509 representations.</summary>
    public static bool NormalizedEquals(string a, string b) =>
        Normalize(a) == Normalize(b);
}

using System.Security.Cryptography.X509Certificates;

namespace Certus.Core.Security;

/// <summary>
/// The extended key usage OIDs the TLS capability ceiling reasons about, in
/// one place so the evaluator, its refusal messages, and the tests cannot
/// drift. This is the first backend home for X.509 EKU constants; the
/// frontend keeps its own label table for display.
/// </summary>
public static class TlsEkuOids
{
    public const string ServerAuth = "1.3.6.1.5.5.7.3.1";
    public const string ClientAuth = "1.3.6.1.5.5.7.3.2";
    public const string AnyPurpose = "2.5.29.37.0";
    public const string EnrollmentAgent = "1.3.6.1.4.1.311.20.2.1";
    public const string SmartCardLogon = "1.3.6.1.4.1.311.20.2.2";
    public const string KdcAuthentication = "1.3.6.1.5.2.3.5";
    public const string CodeSigning = "1.3.6.1.5.5.7.3.3";
    public const string OcspSigning = "1.3.6.1.5.5.7.3.9";
    public const string TimeStamping = "1.3.6.1.5.5.7.3.8";
    public const string KeyRecoveryAgent = "1.3.6.1.4.1.311.21.6";
    public const string Efs = "1.3.6.1.4.1.311.10.3.4";
    public const string CaExchange = "1.3.6.1.4.1.311.21.5";
}

/// <summary>
/// What the ceiling can see of one certificate or template. Null members mean
/// the corresponding extension or attribute is absent, not that it failed to
/// read; a caller that could not determine capability at all must not build
/// an instance and must refuse on its own (fail closed).
/// </summary>
/// <param name="ExtendedKeyUsageOids">EKU OIDs; null means no EKU extension.</param>
/// <param name="KeyUsage">Raw key usage flags; null means no KU extension.</param>
/// <param name="IsCa">BasicConstraints cA; null means no extension.</param>
public sealed record CertificateCapability(
    IReadOnlyList<string>? ExtendedKeyUsageOids,
    X509KeyUsageFlags? KeyUsage,
    bool? IsCa);

/// <summary>
/// The ceiling's verdict: allowed, or a machine readable reason plus a human
/// message naming the concrete offender.
/// </summary>
public sealed record CeilingVerdict(bool Allowed, string? ReasonCode, string? Message)
{
    public static readonly CeilingVerdict Ok = new(true, null, null);
}

/// <summary>
/// The hard floor under everything Ducks issues or revokes: a certificate (or
/// a template's certificates) must be a TLS server or client certificate and
/// nothing else. The rule set, in evaluation order so the message names the
/// most serious offence first:
///
///   1. A CA certificate (BasicConstraints CA=true) is refused.
///   2. A key usage carrying certificate or CRL signing is refused.
///   3. No EKU extension (or an unreadable one) is refused: such a
///      certificate is valid for every purpose.
///   4. A named dangerous EKU (enrollment agent, smart card logon, KDC
///      authentication, code signing, and the rest of the blacklist) is
///      refused with the offender named. The subset rule below already
///      covers these; the explicit list exists for the precise message.
///   5. Any EKU outside serverAuth plus clientAuth is refused, so an unknown
///      or custom OID can never widen what Ducks touches.
///
/// An absent key usage extension passes rule 2 and an absent BasicConstraints
/// passes rule 1: both absences are routine on real TLS leaves, and the EKU
/// subset rule stays the primary gate. The ceiling is unconditional by
/// design; no administrator setting may widen it, and the revocation scope
/// modes only ever narrow within it.
/// </summary>
public static class TlsCapabilityCeiling
{
    /// <summary>
    /// The dangerous EKUs, named for the refusal message. Kept next to the
    /// evaluator so a new entry cannot miss its label.
    /// </summary>
    private static readonly IReadOnlyDictionary<string, string> BlacklistedEkuNames =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [TlsEkuOids.AnyPurpose] = "any purpose",
            [TlsEkuOids.EnrollmentAgent] = "certificate request agent",
            [TlsEkuOids.SmartCardLogon] = "smart card logon",
            [TlsEkuOids.KdcAuthentication] = "KDC authentication",
            [TlsEkuOids.CodeSigning] = "code signing",
            [TlsEkuOids.OcspSigning] = "OCSP signing",
            [TlsEkuOids.TimeStamping] = "time stamping",
            [TlsEkuOids.KeyRecoveryAgent] = "key recovery agent",
            [TlsEkuOids.Efs] = "encrypting file system",
            [TlsEkuOids.CaExchange] = "CA exchange",
        };

    public static CeilingVerdict Evaluate(CertificateCapability capability)
    {
        if (capability.IsCa == true)
        {
            return new CeilingVerdict(false, "ca-certificate",
                "This is a CA certificate (BasicConstraints CA=true).");
        }

        if (capability.KeyUsage is { } keyUsage &&
            (keyUsage & (X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign)) != 0)
        {
            return new CeilingVerdict(false, "key-usage",
                "The key usage includes certificate or CRL signing.");
        }

        if (capability.ExtendedKeyUsageOids is not { Count: > 0 } ekus)
        {
            return new CeilingVerdict(false, "no-eku",
                "There is no extended key usage restriction, so the certificate is valid for every purpose.");
        }

        foreach (var oid in ekus)
        {
            if (BlacklistedEkuNames.TryGetValue(oid, out var name))
            {
                return new CeilingVerdict(false, "blacklisted-eku",
                    $"The extended key usage includes {name} ({oid}).");
            }
        }

        foreach (var oid in ekus)
        {
            if (!string.Equals(oid, TlsEkuOids.ServerAuth, StringComparison.Ordinal) &&
                !string.Equals(oid, TlsEkuOids.ClientAuth, StringComparison.Ordinal))
            {
                return new CeilingVerdict(false, "eku-outside-ceiling",
                    $"The extended key usage {oid} is outside the TLS ceiling (server and client authentication only).");
            }
        }

        return CeilingVerdict.Ok;
    }
}

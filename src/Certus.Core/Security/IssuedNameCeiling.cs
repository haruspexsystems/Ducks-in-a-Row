using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

namespace Certus.Core.Security;

/// <summary>
/// The issued side twin of the finalize dns path's name checks: the leaf guard
/// applies these to the certificate the CA actually returned, not the CSR, so a
/// name the CA added or substituted is caught even though the CSR was clean.
///
/// The finalize validates the CSR, but ADCS reads carriers the product does not
/// (a SAN under szOID_CERT_EXTENSIONS, measured on lab 2019, issue #548), and a
/// certificate another tool enrolled against the same CA is synced too. So the
/// guard re-reads the issued certificate and refuses, with a reason 5 auto
/// revoke, when any of these hold for a dns order:
///
///   1. The SAN carries an entry that is not a dNSName (an otherName such as a
///      UPN, an rfc822Name, an IP, a directoryName). A dns order authorizes
///      none of these, and this is the entry the carrier smuggling route
///      produced in the lab.
///   2. A dNSName in the SAN is not one of the order's dns identifiers.
///   3. A subject common name is not one of the order's dns identifiers, the
///      same membership rule the finalize applies to the CSR.
///
/// Device orders are judged by their own rules (the attested key and the
/// PermanentIdentifier) and never reach here. The verdict is a
/// <see cref="CeilingVerdict"/> so the one breach path,
/// <c>RefuseIssuedCertificateAsync</c>, handles a name breach and a capability
/// breach alike.
/// </summary>
public static class IssuedNameCeiling
{
    private const string SubjectAltNameOid = "2.5.29.17";

    /// <summary>
    /// Judges one issued certificate's names against the order's dns
    /// identifiers. <paramref name="orderDnsIdentifiers"/> must already be
    /// trimmed and lower cased, the form the finalize compares in. A
    /// certificate that cannot be read here is refused (fail closed); the leaf
    /// guard has already parsed it for capability, so this is defensive.
    /// </summary>
    public static CeilingVerdict Evaluate(byte[] issuedDer, ISet<string> orderDnsIdentifiers)
    {
        X509Certificate2 leaf;
        try
        {
            leaf = X509CertificateLoader.LoadCertificate(issuedDer);
        }
        catch (CryptographicException)
        {
            return new CeilingVerdict(false, "name-unreadable",
                "The issued certificate could not be read to check its names against the order.");
        }

        using (leaf)
        {
            try
            {
                var sanExtension = leaf.Extensions[SubjectAltNameOid];
                if (sanExtension != null)
                {
                    var names = GeneralNames.GetInstance(
                        Asn1Object.FromByteArray(sanExtension.RawData));
                    foreach (var name in names.GetNames())
                    {
                        if (name.TagNo != GeneralName.DnsName)
                        {
                            return new CeilingVerdict(false, "name-non-dns-san",
                                "The issued certificate carries a subject alternative name that is " +
                                "not a DNS name, which this dns order did not authorize.");
                        }

                        var dns = name.Name.ToString()!.Trim().ToLowerInvariant();
                        if (!orderDnsIdentifiers.Contains(dns))
                        {
                            return new CeilingVerdict(false, "name-dns-mismatch",
                                $"The issued certificate carries a DNS name ({dns}) that is not one " +
                                "of the order's identifiers.");
                        }
                    }
                }

                var subject = X509Name.GetInstance(
                    Asn1Object.FromByteArray(leaf.SubjectName.RawData));
                foreach (var value in subject.GetValueList(X509Name.CN))
                {
                    var cn = value!.ToString()!.Trim().ToLowerInvariant();
                    if (cn.Length > 0 && !orderDnsIdentifiers.Contains(cn))
                    {
                        return new CeilingVerdict(false, "name-cn-mismatch",
                            $"The issued certificate subject common name ({cn}) is not one of the " +
                            "order's identifiers.");
                    }
                }
            }
            catch (Exception ex) when (
                ex is ArgumentException or InvalidOperationException or InvalidCastException or IOException)
            {
                // The same filter MockAdcsClient.FindRequestedSan and
                // CsrHelper.TryReadPermanentIdentifier use for a BouncyCastle
                // parse. An escaping exception here would fail the order without
                // revoking the live leaf, so the parse must refuse, never throw.
                return new CeilingVerdict(false, "name-unreadable",
                    "The issued certificate's names could not be parsed to check them against the order.");
            }

            return CeilingVerdict.Ok;
        }
    }
}

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkcs;

namespace Certus.Core.Acme.Services;

/// <summary>
/// Utility for parsing and validating PKCS#10 Certificate Signing Requests.
/// </summary>
public static class CsrHelper
{
    /// <summary>
    /// Extracts Subject Alternative Names (DNS names) from a DER encoded CSR.
    /// Returns the list of DNS names found in the SAN extension.
    /// If no SAN extension exists, falls back to the CN from the subject.
    /// </summary>
    public static IReadOnlyList<string> ExtractSansFromCsr(byte[] csrDer)
    {
        var csr = new Pkcs10CertificationRequest(csrDer);

        // Verify the CSR signature (proves the requester holds the private key)
        if (!csr.Verify())
            throw new InvalidOperationException("CSR signature verification failed.");

        var sans = new List<string>();

        // Look for SAN extension in the CSR attributes
        var info = csr.GetCertificationRequestInfo();
        var attributes = info.Attributes;

        if (attributes != null)
        {
            foreach (var attr in attributes)
            {
                if (attr is not DerSequence seq || seq.Count < 2)
                    continue;

                var oid = (seq[0] as DerObjectIdentifier)?.Id;
                if (oid != PkcsObjectIdentifiers.Pkcs9AtExtensionRequest.Id)
                    continue;

                // The value is a SET containing a SEQUENCE of extensions
                var extSet = seq[1] as DerSet;
                if (extSet == null || extSet.Count == 0) continue;

                var extensions = X509Extensions.GetInstance(extSet[0]);
                var sanExtension = extensions.GetExtension(X509Extensions.SubjectAlternativeName);
                if (sanExtension == null) continue;

                var sanSequence = GeneralNames.GetInstance(sanExtension.GetParsedValue());
                foreach (var name in sanSequence.GetNames())
                {
                    // Tag 2 = dNSName
                    if (name.TagNo == GeneralName.DnsName)
                    {
                        sans.Add(name.Name.ToString()!);
                    }
                }
            }
        }

        // Fallback: extract CN from subject if no SANs found
        if (sans.Count == 0)
        {
            var subject = info.Subject;
            var cnValues = subject.GetValueList(X509Name.CN);
            if (cnValues.Count > 0)
            {
                sans.Add(cnValues[0]!.ToString()!);
            }
        }

        return sans;
    }
}

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkcs;

namespace Certus.Core.Security;

/// <summary>
/// The key half of the leaf guard (issue #604): the certificate an order
/// collects must carry the public key of the CSR that order claimed, or it is
/// not that order's certificate at all.
///
/// A CA request id is unique only within one CA, and the pending issuance sweep
/// asks whichever CA the install is configured with now. After the install is
/// pointed at another CA, an order held at the old one collects the new CA's
/// request of the same number: a certificate somebody else enrolled. The
/// ceilings cannot tell, and worse, their breach arm revokes, so a certificate
/// whose names were not the order's was revoked at a CA where it belonged to a
/// stranger. This runs before them and its refusal never revokes.
///
/// The comparison is the algorithm and the subjectPublicKey bits, which decide
/// the key. The algorithm parameters must agree too, except that an absent
/// parameter and an explicit NULL count as the same: RFC 3279 asks for NULL
/// with rsaEncryption, some encoders omit it, and a CA that normalised one to
/// the other would otherwise fail a certificate that is genuinely the order's.
/// </summary>
public static class IssuedKeyCheck
{
    /// <summary>
    /// Judges one issued certificate against the CSR its order claimed.
    /// <paramref name="orderCsrDer"/> is the CSR as the claim stored it; null
    /// when nothing is stored, which erasing a deactivated account does to every
    /// one of its orders (#637). Anything that cannot be compared is refused:
    /// the caller refuses without revoking, so failing closed costs a delivery,
    /// never a stranger's certificate.
    /// </summary>
    public static CeilingVerdict Evaluate(byte[]? issuedDer, byte[]? orderCsrDer)
    {
        if (orderCsrDer is not { Length: > 0 })
            return new CeilingVerdict(false, "key-no-csr",
                "The order's CSR is no longer stored, so the issued certificate's key cannot " +
                "be checked against it.");

        SubjectPublicKeyInfo requested;
        SubjectPublicKeyInfo issued;
        try
        {
            requested = new Pkcs10CertificationRequest(orderCsrDer)
                .GetCertificationRequestInfo().SubjectPublicKeyInfo;
            issued = X509CertificateStructure.GetInstance(Asn1Object.FromByteArray(issuedDer ?? []))
                .SubjectPublicKeyInfo;
        }
        catch (Exception)
        {
            // Wider than the filter IssuedNameCeiling uses, on purpose. This runs
            // before every other parse of the leaf, so an exception escaping here
            // would leave a held order in processing, failing the same way on
            // every sweep tick until it expires. Refusing costs one delivery.
            return new CeilingVerdict(false, "key-unreadable",
                "The issued certificate's key could not be read to check it against the order's CSR.");
        }

        return SameKey(requested, issued)
            ? CeilingVerdict.Ok
            : new CeilingVerdict(false, "key-mismatch",
                "The issued certificate carries a public key other than the one in the order's CSR.");
    }

    internal static bool SameKey(SubjectPublicKeyInfo requested, SubjectPublicKeyInfo issued)
    {
        if (!requested.Algorithm.Algorithm.Equals(issued.Algorithm.Algorithm))
            return false;

        if (!SameParameters(requested.Algorithm.Parameters, issued.Algorithm.Parameters))
            return false;

        return requested.PublicKey.GetBytes().AsSpan()
            .SequenceEqual(issued.PublicKey.GetBytes());
    }

    private static bool SameParameters(Asn1Encodable? requested, Asn1Encodable? issued)
    {
        var requestedAbsent = requested is null || requested is Asn1Null;
        var issuedAbsent = issued is null || issued is Asn1Null;
        if (requestedAbsent || issuedAbsent)
            return requestedAbsent && issuedAbsent;

        return requested!.ToAsn1Object().Equals(issued!.ToAsn1Object());
    }
}

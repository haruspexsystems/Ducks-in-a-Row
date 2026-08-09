using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Certus.Core.Acme.Attestation;
using Certus.Core.Acme.Crypto;

namespace Certus.Core.Tests.Acme.Attestation;

/// <summary>
/// Builds synthetic apple format attestation material: a self signed root,
/// optionally an intermediate, and device leaf certificates carrying the
/// real Apple extension OIDs, wrapped into a CBOR attestation object. The
/// leaves share <see cref="AppleAttestationOids"/> with the verifier, so a
/// correction to a recorded Apple fact updates both sides at once. Also
/// reused by the Phase 4 integration tests.
/// </summary>
internal static class SyntheticAttestationBuilder
{
    /// <summary>A self signed CA usable as a trust anchor; holds its private key.</summary>
    public static X509Certificate2 CreateRoot(string subject = "CN=Synthetic Attestation Root")
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA384);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(
            certificateAuthority: true, false, 0, critical: true));
        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));
        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-30),
            DateTimeOffset.UtcNow.AddYears(10));
    }

    /// <summary>
    /// An intermediate CA signed by <paramref name="issuer"/>, returned with
    /// its private key so it can in turn sign leaves (the PFX round trip
    /// detaches the certificate from the ephemeral signing key handle).
    /// </summary>
    public static X509Certificate2 CreateIntermediate(
        X509Certificate2 issuer, string subject = "CN=Synthetic Attestation CA")
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(
            certificateAuthority: true, false, 0, critical: true));

        using var withoutKey = request.Create(
            issuer,
            DateTimeOffset.UtcNow.AddDays(-7),
            DateTimeOffset.UtcNow.AddYears(5),
            RandomSerial());
        using var withKey = withoutKey.CopyWithPrivateKey(key);
        return X509CertificateLoader.LoadPkcs12(
            withKey.Export(X509ContentType.Pfx),
            null,
            X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);
    }

    /// <summary>
    /// A device leaf signed by <paramref name="issuer"/>. Every Apple
    /// extension is optional so tests can build each malformation; values
    /// are written as the raw extension bytes, the shape the verifier reads.
    /// Pass <paramref name="key"/> (caller owned, not disposed here) when
    /// the test later needs the attested private key, for example to sign
    /// the finalize CSR with the key the attestation vouched for.
    /// </summary>
    public static X509Certificate2 CreateLeaf(
        X509Certificate2 issuer,
        string? serialNumber = null,
        string? udid = null,
        byte[]? nonce = null,
        string? sepOsVersion = null,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null,
        ECDsa? key = null)
    {
        var ownsKey = key == null;
        var leafKey = key ?? ECDsa.Create(ECCurve.NamedCurves.nistP256);
        try
        {
            var request = new CertificateRequest(
                "CN=Synthetic Device", leafKey, HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(
                certificateAuthority: false, false, 0, critical: true));
            if (serialNumber is not null)
                request.CertificateExtensions.Add(
                    RawExtension(AppleAttestationOids.SerialNumber, Encoding.UTF8.GetBytes(serialNumber)));
            if (udid is not null)
                request.CertificateExtensions.Add(
                    RawExtension(AppleAttestationOids.Udid, Encoding.UTF8.GetBytes(udid)));
            if (sepOsVersion is not null)
                request.CertificateExtensions.Add(
                    RawExtension(AppleAttestationOids.SepOsVersion, Encoding.UTF8.GetBytes(sepOsVersion)));
            if (nonce is not null)
                request.CertificateExtensions.Add(RawExtension(AppleAttestationOids.Nonce, nonce));

            return request.Create(
                issuer,
                notBefore ?? DateTimeOffset.UtcNow.AddHours(-1),
                notAfter ?? DateTimeOffset.UtcNow.AddDays(7),
                RandomSerial());
        }
        finally
        {
            if (ownsKey)
                leafKey.Dispose();
        }
    }

    /// <summary>The nonce a genuine device would carry for this challenge token.</summary>
    public static byte[] NonceFor(string token) =>
        SHA256.HashData(Encoding.ASCII.GetBytes(token));

    /// <summary>
    /// The CBOR attestation object: {fmt, attStmt: {x5c}}, optionally with
    /// the authData member clients SHOULD omit and an unknown future member.
    /// </summary>
    public static byte[] BuildAttestationObject(
        string format,
        IReadOnlyList<X509Certificate2> x5c,
        bool includeAuthData = false,
        bool includeUnknownMember = false)
    {
        var writer = new CborWriter(CborConformanceMode.Lax);
        writer.WriteStartMap(2 + (includeAuthData ? 1 : 0) + (includeUnknownMember ? 1 : 0));
        writer.WriteTextString("fmt");
        writer.WriteTextString(format);
        writer.WriteTextString("attStmt");
        writer.WriteStartMap(1);
        writer.WriteTextString("x5c");
        writer.WriteStartArray(x5c.Count);
        foreach (var certificate in x5c)
            writer.WriteByteString(certificate.RawData);
        writer.WriteEndArray();
        writer.WriteEndMap();
        if (includeAuthData)
        {
            writer.WriteTextString("authData");
            writer.WriteByteString(new byte[16]);
        }
        if (includeUnknownMember)
        {
            writer.WriteTextString("futureMember");
            writer.WriteInt32(7);
        }
        writer.WriteEndMap();
        return writer.Encode();
    }

    /// <summary>The attestation object as the base64url string a client POSTs.</summary>
    public static string ToChallengePayload(byte[] attestationObject) =>
        JwsService.Base64UrlEncode(attestationObject);

    /// <summary>The certificate as PEM, the trust anchor table's storage form.</summary>
    public static string ToPem(X509Certificate2 certificate) =>
        new(PemEncoding.Write("CERTIFICATE", certificate.RawData));

    private static byte[] RandomSerial() => RandomNumberGenerator.GetBytes(12);

    private static X509Extension RawExtension(string oid, byte[] value) =>
        new(new Oid(oid, null), value, critical: false);
}

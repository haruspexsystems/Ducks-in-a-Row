using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Certus.Core.Acme.Attestation;

/// <summary>
/// Verifies the "apple" attestation format (Apple Managed Device
/// Attestation). The statement carries an x5c chain of DER certificates,
/// leaf first; the leaf was issued by Apple's attestation CA for the device
/// key and carries the device serial number, the UDID, and a freshness
/// nonce in private extensions (see <see cref="AppleAttestationOids"/>).
///
/// Verification: the chain must build to the embedded Apple Enterprise
/// Attestation Root CA or to an enabled custom anchor, with extended key
/// usage treated as any and no revocation check (Apple publishes no CRL for
/// these); the nonce extension must equal SHA-256 of the raw challenge
/// token bytes; and the order identifier must octet match either the
/// attested serial number or the attested UDID (deployed practice: MDM
/// operators use either as the ClientIdentifier).
/// </summary>
public sealed class AppleAttestationVerifier : IAttestationFormatVerifier
{
    /// <summary>The CBOR "fmt" string of this format.</summary>
    public const string FormatName = "apple";

    private const string RootResourceName =
        "Certus.Core.Acme.Attestation.AppleEnterpriseAttestationRootCa.pem";

    /// <summary>
    /// The embedded Apple root, pin checked once per process. A mismatch
    /// (tampered or mispackaged resource) throws, so every construction of
    /// the verifier fails and no apple attestation can ever verify against
    /// an unpinned root.
    /// </summary>
    private static readonly Lazy<X509Certificate2> EmbeddedRoot = new(LoadEmbeddedRoot);

    private readonly X509Certificate2 _appleRoot;

    public AppleAttestationVerifier()
    {
        // Resolve the lazy in the constructor so the pin check runs at host
        // startup (the hosts construct the verifier registry while starting),
        // not on the first device order.
        _appleRoot = EmbeddedRoot.Value;
    }

    public string Format => FormatName;

    public Task<AttestationVerificationResult> VerifyAsync(
        AttestationContext context,
        CancellationToken cancellationToken = default)
    {
        // All work is local parsing and chain building; the Task shape exists
        // for formats that need I/O.
        return Task.FromResult(Verify(context));
    }

    private AttestationVerificationResult Verify(AttestationContext context)
    {
        List<byte[]> x5c;
        try
        {
            x5c = ReadX5c(context.Envelope.AttStmt);
        }
        catch (AttestationParseException ex)
        {
            return AttestationVerificationResult.Failure(ex.Message);
        }

        if (x5c.Count == 0)
            return AttestationVerificationResult.Failure(
                "The apple attestation statement carries no certificate chain.");

        var certificates = new List<X509Certificate2>(x5c.Count);
        try
        {
            foreach (var der in x5c)
            {
                try
                {
                    certificates.Add(X509CertificateLoader.LoadCertificate(der));
                }
                catch (CryptographicException)
                {
                    return AttestationVerificationResult.Failure(
                        "A certificate in the apple attestation chain could not be parsed.");
                }
            }

            var leaf = certificates[0];

            using (var chain = new X509Chain())
            {
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.CustomTrustStore.Add(_appleRoot);
                foreach (var anchor in context.AdditionalTrustAnchors)
                    chain.ChainPolicy.CustomTrustStore.Add(anchor);
                for (var i = 1; i < certificates.Count; i++)
                    chain.ChainPolicy.ExtraStore.Add(certificates[i]);

                if (!chain.Build(leaf))
                {
                    var status = string.Join(", ", chain.ChainStatus.Select(s => s.Status));
                    return AttestationVerificationResult.Failure(
                        $"The attestation certificate chain is not trusted: {status}.");
                }
            }

            // Freshness: the nonce extension must be SHA-256 over the raw token
            // string bytes. The extension value is the raw digest, not a DER
            // wrapped form (step-ca reads it the same way against live devices).
            var nonceExtension = leaf.Extensions[AppleAttestationOids.Nonce];
            if (nonceExtension is null)
                return AttestationVerificationResult.Failure(
                    "The attestation certificate carries no nonce extension.");

            var expectedNonce = SHA256.HashData(Encoding.ASCII.GetBytes(context.Token));
            if (!CryptographicOperations.FixedTimeEquals(nonceExtension.RawData, expectedNonce))
                return AttestationVerificationResult.Failure(
                    "The attestation nonce does not match the challenge token.");

            var serialNumber = ReadStringExtension(leaf, AppleAttestationOids.SerialNumber);
            var udid = ReadStringExtension(leaf, AppleAttestationOids.Udid);
            var sepOsVersion = ReadStringExtension(leaf, AppleAttestationOids.SepOsVersion);

            // Octet exact match against serial or UDID. A value with an
            // "/assigner-OID" suffix therefore never matches an Apple
            // attestation, which is the honest answer: the device did not
            // attest that string.
            var expected = context.ExpectedIdentifierValue;
            var matches =
                (serialNumber is not null && string.Equals(expected, serialNumber, StringComparison.Ordinal)) ||
                (udid is not null && string.Equals(expected, udid, StringComparison.Ordinal));
            if (!matches)
                return AttestationVerificationResult.Failure(
                    "The attested device identifiers do not match the order identifier.");

            var properties = new Dictionary<string, string>();
            if (serialNumber is not null)
                properties["serialNumber"] = serialNumber;
            if (udid is not null)
                properties["udid"] = udid;
            if (sepOsVersion is not null)
                properties["sepOsVersion"] = sepOsVersion;

            return AttestationVerificationResult.Success(
                expected,
                leaf.PublicKey.ExportSubjectPublicKeyInfo(),
                properties);
        }
        finally
        {
            foreach (var certificate in certificates)
                certificate.Dispose();
        }
    }

    /// <summary>
    /// Reads the "x5c" member of the apple attestation statement: an array
    /// of DER certificate byte strings, leaf first.
    /// </summary>
    private static List<byte[]> ReadX5c(byte[] attStmt)
    {
        try
        {
            var reader = new CborReader(attStmt, CborConformanceMode.Lax);
            reader.ReadStartMap();

            var x5c = new List<byte[]>();
            while (reader.PeekState() != CborReaderState.EndMap)
            {
                var key = reader.ReadTextString();
                if (key == "x5c")
                {
                    reader.ReadStartArray();
                    while (reader.PeekState() != CborReaderState.EndArray)
                        x5c.Add(reader.ReadByteString());
                    reader.ReadEndArray();
                }
                else
                {
                    reader.SkipValue();
                }
            }
            reader.ReadEndMap();

            return x5c;
        }
        catch (Exception ex) when (ex is CborContentException or InvalidOperationException)
        {
            throw new AttestationParseException(
                "The apple attestation statement is not well formed.", ex);
        }
    }

    /// <summary>
    /// Reads a leaf extension whose value is a raw string (the Apple device
    /// extensions carry the bare bytes, with no DER string wrapper).
    /// </summary>
    private static string? ReadStringExtension(X509Certificate2 leaf, string oid)
    {
        var extension = leaf.Extensions[oid];
        if (extension is null || extension.RawData.Length == 0)
            return null;
        return Encoding.UTF8.GetString(extension.RawData);
    }

    private static X509Certificate2 LoadEmbeddedRoot()
    {
        using var stream = typeof(AppleAttestationVerifier).Assembly
            .GetManifestResourceStream(RootResourceName)
            ?? throw new InvalidOperationException(
                "The embedded Apple attestation root resource is missing from the assembly.");
        using var reader = new StreamReader(stream);

        var root = X509Certificate2.CreateFromPem(reader.ReadToEnd());

        // The pin is over the DER bytes, so PEM line ending differences
        // cannot move it. Fail closed: a mismatch throws and the verifier
        // cannot be constructed.
        var fingerprint = Convert.ToHexString(SHA256.HashData(root.RawData)).ToLowerInvariant();
        if (fingerprint != AppleAttestationOids.RootSha256Fingerprint)
        {
            root.Dispose();
            throw new InvalidOperationException(
                $"The embedded Apple attestation root failed its SHA-256 pin check " +
                $"(got {fingerprint}); refusing to trust it.");
        }

        return root;
    }
}

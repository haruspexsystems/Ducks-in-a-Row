using System.Formats.Asn1;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace Certus.Core.Modules;

/// <summary>
/// The verdict on one module file's signature. <see cref="FoundPublisher"/> is the CN of the
/// certificate that signed the file, when there was one, reduced to printable text and capped so a
/// module cannot write what it likes into the log line that names it.
/// </summary>
public sealed record ModuleSignatureVerdict(bool IsValid, string FileName, string? FoundPublisher, string? Reason)
{
    public static ModuleSignatureVerdict Valid(string fileName, string publisher) => new(true, fileName, publisher, null);

    public static ModuleSignatureVerdict Refused(string fileName, string? foundPublisher, string reason) =>
        new(false, fileName, foundPublisher, reason);
}

/// <summary>
/// Verifies the Authenticode signature of a paid module's files before any of them is loaded
/// (issue #636, CRA risk R13). It is the product's own check, not the host's: WDAC and AppLocker
/// publisher rules evaluate the same signed file, but only where an operator has written such a
/// policy, and most have not.
///
/// <para>The check is done in managed code rather than through WinVerifyTrust, because the test suite
/// must prove it with a certificate chain of its own, and WinVerifyTrust trusts only the machine's
/// root store, which no test may change. The rules are Authenticode's: the PKCS#7 in the PE file's
/// certificate table signs an SpcIndirectDataContent whose digest is the file's Authenticode hash,
/// which skips the checksum field, the certificate table's directory entry and the table itself.
/// The signer's certificate chain must end in a root the <see cref="ModuleSignaturePolicy"/> trusts
/// and carry the code signing usage, and the subject's CN and O must each be the expected
/// publisher.</para>
///
/// <para>A timestamp is required, in the RFC 3161 form signtool's <c>/tr</c> writes and the release
/// build uses. Both chains, the signer's and the timestamp authority's, are judged at the time the
/// timestamp certifies, which is Authenticode's rule: a module signed while the certificate was
/// valid stays loadable after that certificate expires, and a signature made with an already
/// expired certificate is refused however recent the file. A signature with no timestamp is refused
/// outright, because without one the module would stop loading on the day the certificate expired.
/// Revocation is checked only against what Windows has cached: a revocation fetch is a call to a host
/// the operator did not configure, and the service makes none of those.</para>
///
/// <para>The manifest, module.json, is not a PE file and cannot carry an Authenticode signature, so it
/// ships with a detached CMS signature beside it, module.json.p7, held to the same policy by
/// <see cref="VerifyDetached"/>. Every other file the manifest lists is covered by the hash the
/// signed manifest records.</para>
/// </summary>
public static class ModuleSignatureVerifier
{
    /// <summary>
    /// The detached signature of a module's manifest, beside it in the module folder. The name is
    /// the one <c>signtool sign /p7 &lt;folder&gt; /p7ce DetachedSignedData /p7co 1.2.840.113549.1.7.1
    /// module.json</c> writes, so the Certus-Commercial build (#496) signs the manifest in the same
    /// step as the assemblies and renames nothing.
    /// </summary>
    public const string ManifestSignatureFileName = "module.json.p7";

    private const string SignedDataOid = "1.2.840.113549.1.7.2";
    private const string SpcIndirectDataOid = "1.3.6.1.4.1.311.2.1.4";
    private const string Rfc3161CounterSignatureOid = "1.3.6.1.4.1.311.3.3.1";
    private const string CodeSigningUsage = "1.3.6.1.5.5.7.3.3";
    private const string TimeStampingUsage = "1.3.6.1.5.5.7.3.8";
    private const string CommonNameOid = "2.5.4.3";
    private const string OrganisationOid = "2.5.4.10";

    private const ushort CertificateRevision = 0x0200;
    private const ushort CertificateTypePkcsSignedData = 0x0002;
    private const int MaxPublisherLength = 64;

    /// <summary>
    /// Checks every file of a module that <paramref name="policy"/> covers: the manifest against
    /// its detached signature, then each listed .dll and .exe. Returns null when all pass, or the
    /// first refusal.
    /// </summary>
    public static ModuleSignatureVerdict? CheckModule(string moduleFolder, ModuleManifest manifest, ModuleSignaturePolicy policy)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(moduleFolder);
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(policy);

        if (!policy.IsEnforced)
            return null;

        var folder = Path.GetFullPath(moduleFolder);
        var manifestPath = Path.Combine(folder, "module.json");
        var manifestVerdict = VerifyDetached(manifestPath, Path.Combine(folder, ManifestSignatureFileName), policy);
        if (!manifestVerdict.IsValid)
            return manifestVerdict;

        foreach (var file in manifest.Files)
        {
            var extension = Path.GetExtension(file.Path);
            if (!(extension.Equals(".dll", StringComparison.OrdinalIgnoreCase) || extension.Equals(".exe", StringComparison.OrdinalIgnoreCase)))
                continue;

            var verdict = VerifyPortableExecutable(Path.GetFullPath(Path.Combine(folder, file.Path)), policy);
            if (!verdict.IsValid)
                return verdict;
        }

        return null;
    }

    /// <summary>Verifies the embedded Authenticode signature of the PE file at <paramref name="path"/>.</summary>
    public static ModuleSignatureVerdict VerifyPortableExecutable(string path, ModuleSignaturePolicy policy)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(policy);
        var fileName = Path.GetFileName(path);

        byte[] image;
        try
        {
            image = File.ReadAllBytes(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return ModuleSignatureVerdict.Refused(fileName, null, $"could not be read ({ex.Message})");
        }

        List<byte[]> signatures;
        AuthenticodeLayout layout;
        try
        {
            layout = AuthenticodeLayout.Read(image);
            signatures = layout.ReadSignatures(image);
        }
        catch (Exception ex) when (ex is BadImageFormatException or InvalidDataException or ArgumentOutOfRangeException)
        {
            return ModuleSignatureVerdict.Refused(fileName, null, $"is not a well formed PE file ({ex.Message})");
        }

        if (signatures.Count == 0)
            return ModuleSignatureVerdict.Refused(fileName, null, "is not signed");

        // The certificate table may hold more than one entry. One that satisfies the policy is
        // enough; otherwise the first refusal is the one reported, so a wrongly signed file explains
        // itself in one line. A signature nested inside another's unsigned attributes (the Windows 7
        // era SHA-1 plus SHA-256 pattern) is not walked: Haruspex signs each file once, with SHA-256.
        ModuleSignatureVerdict? first = null;
        foreach (var encoded in signatures)
        {
            var verdict = VerifyAuthenticodeSignature(encoded, image, layout, fileName, policy);
            if (verdict.IsValid)
                return verdict;
            first ??= verdict;
        }

        return first!;
    }

    /// <summary>
    /// Verifies the detached CMS signature at <paramref name="signaturePath"/> over the bytes of
    /// the file at <paramref name="path"/>.
    /// </summary>
    public static ModuleSignatureVerdict VerifyDetached(string path, string signaturePath, ModuleSignaturePolicy policy)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentException.ThrowIfNullOrWhiteSpace(signaturePath);
        ArgumentNullException.ThrowIfNull(policy);
        var fileName = Path.GetFileName(path);

        if (!File.Exists(signaturePath))
            return ModuleSignatureVerdict.Refused(fileName, null, $"has no signature file ({Path.GetFileName(signaturePath)} is missing)");

        byte[] content;
        byte[] encoded;
        try
        {
            content = File.ReadAllBytes(path);
            encoded = File.ReadAllBytes(signaturePath);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return ModuleSignatureVerdict.Refused(fileName, null, $"could not be read ({ex.Message})");
        }

        SignedCms cms;
        try
        {
            cms = DecodeDetached(content, encoded);
        }
        catch (CryptographicException ex)
        {
            return ModuleSignatureVerdict.Refused(fileName, null, $"has a signature file that is not a CMS signature ({ex.Message})");
        }

        return VerifySigner(cms, fileName, policy, static (_, _) => null);
    }

    /// <summary>
    /// Decodes a detached signature over <paramref name="content"/>. <c>signtool sign /p7 ... /p7ce
    /// DetachedSignedData</c> writes the SignedData alone, without the ContentInfo wrapper RFC 5652
    /// puts around it and <see cref="SignedCms.Decode(byte[])"/> expects, so a file that does not
    /// decode as it is gets the wrapper added and one more try. Measured on the Windows 11 SDK
    /// signtool (10.0.26100) against this code's own output, which carries the wrapper.
    /// </summary>
    private static SignedCms DecodeDetached(byte[] content, byte[] encoded)
    {
        var cms = new SignedCms(new ContentInfo(content), detached: true);
        try
        {
            cms.Decode(encoded);
            return cms;
        }
        catch (CryptographicException)
        {
            var writer = new AsnWriter(AsnEncodingRules.DER);
            writer.PushSequence();
            writer.WriteObjectIdentifier(SignedDataOid);
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            writer.WriteEncodedValue(encoded);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            writer.PopSequence();

            cms = new SignedCms(new ContentInfo(content), detached: true);
            cms.Decode(writer.Encode());
            return cms;
        }
    }

    private static ModuleSignatureVerdict VerifyAuthenticodeSignature(
        byte[] encoded, byte[] image, AuthenticodeLayout layout, string fileName, ModuleSignaturePolicy policy)
    {
        SignedCms cms;
        try
        {
            cms = new SignedCms();
            cms.Decode(encoded);
        }
        catch (CryptographicException ex)
        {
            return ModuleSignatureVerdict.Refused(fileName, null, $"carries a signature that could not be decoded ({ex.Message})");
        }

        if (!string.Equals(cms.ContentInfo.ContentType.Value, SpcIndirectDataOid, StringComparison.Ordinal))
            return ModuleSignatureVerdict.Refused(fileName, null, "carries a signature that is not an Authenticode signature");

        // The digest the signature vouches for must be the file's Authenticode hash, or the
        // signature belongs to other bytes: a file changed after signing, or a signature moved
        // from another file.
        return VerifySigner(cms, fileName, policy, (signed, name) =>
        {
            HashAlgorithmName algorithm;
            byte[] expected;
            try
            {
                (algorithm, expected) = ReadIndirectData(signed.ContentInfo.Content);
            }
            catch (Exception ex) when (ex is AsnContentException or CryptographicException)
            {
                return $"carries a signature whose content could not be read ({ex.Message})";
            }

            var actual = layout.ComputeHash(image, algorithm);
            return CryptographicOperations.FixedTimeEquals(actual, expected)
                ? null
                : "does not match its signature: the file was changed after it was signed";
        });
    }

    /// <summary>
    /// The checks every signature form shares, in the order that makes the refusal most telling:
    /// the signature verifies against its own certificate, the publisher is the expected one, the
    /// content is what was signed, a timestamp is present and verifies, and both chains build to a
    /// trusted root at the timestamp's time.
    /// </summary>
    private static ModuleSignatureVerdict VerifySigner(
        SignedCms cms, string fileName, ModuleSignaturePolicy policy, Func<SignedCms, string, string?> checkContent)
    {
        if (cms.SignerInfos.Count == 0)
            return ModuleSignatureVerdict.Refused(fileName, null, "carries a signature with no signer");

        var signer = cms.SignerInfos[0];
        var certificate = signer.Certificate;
        if (certificate is null)
            return ModuleSignatureVerdict.Refused(fileName, null, "carries a signature whose certificate is not included");

        var (commonName, organisation) = ReadSubject(certificate);
        var found = Printable(commonName);

        try
        {
            signer.CheckSignature(verifySignatureOnly: true);
        }
        catch (CryptographicException ex)
        {
            return ModuleSignatureVerdict.Refused(fileName, found, $"carries a signature that does not verify ({ex.Message})");
        }

        if (!string.Equals(commonName, policy.CommonName, StringComparison.Ordinal))
            return ModuleSignatureVerdict.Refused(fileName, found, $"is signed by '{found}', not by '{policy.CommonName}'");

        if (!string.Equals(organisation, policy.Organisation, StringComparison.Ordinal))
        {
            return ModuleSignatureVerdict.Refused(fileName, found,
                $"is signed by '{found}' of organisation '{Printable(organisation)}', not by '{policy.Organisation}'");
        }

        if (checkContent(cms, fileName) is { } contentRefusal)
            return ModuleSignatureVerdict.Refused(fileName, found, contentRefusal);

        var timestamp = ReadTimestamp(signer, policy, out var timestampRefusal);
        if (timestamp is null)
            return ModuleSignatureVerdict.Refused(fileName, found, timestampRefusal!);

        if (BuildChain(certificate, cms.Certificates, policy, CodeSigningUsage, timestamp.Value) is { } chainRefusal)
            return ModuleSignatureVerdict.Refused(fileName, found, $"is signed with a certificate that is not trusted: {chainRefusal}");

        return ModuleSignatureVerdict.Valid(fileName, found);
    }

    /// <summary>
    /// The time the signature's RFC 3161 timestamp certifies, with the timestamp authority's own
    /// signature and chain verified, or null with the reason.
    /// </summary>
    private static DateTimeOffset? ReadTimestamp(SignerInfo signer, ModuleSignaturePolicy policy, out string? refusal)
    {
        AsnEncodedData? attribute = null;
        foreach (var unsigned in signer.UnsignedAttributes)
        {
            if (string.Equals(unsigned.Oid.Value, Rfc3161CounterSignatureOid, StringComparison.Ordinal) && unsigned.Values.Count > 0)
            {
                attribute = unsigned.Values[0];
                break;
            }
        }

        if (attribute is null)
        {
            refusal = "carries no timestamp";
            return null;
        }

        Rfc3161TimestampToken? token;
        X509Certificate2? authority;
        try
        {
            if (!Rfc3161TimestampToken.TryDecode(attribute.RawData, out token, out _) || token is null)
            {
                refusal = "carries a timestamp that could not be decoded";
                return null;
            }

            if (!token.VerifySignatureForSignerInfo(signer, out authority) || authority is null)
            {
                refusal = "carries a timestamp that does not verify";
                return null;
            }
        }
        catch (CryptographicException ex)
        {
            refusal = $"carries a timestamp that does not verify ({ex.Message})";
            return null;
        }

        var at = token.TokenInfo.Timestamp;
        if (BuildChain(authority, token.AsSignedCms().Certificates, policy, TimeStampingUsage, at) is { } chainRefusal)
        {
            refusal = $"carries a timestamp from an authority that is not trusted: {chainRefusal}";
            return null;
        }

        refusal = null;
        return at;
    }

    /// <summary>
    /// Builds <paramref name="leaf"/>'s chain at <paramref name="at"/> to the policy's roots, with
    /// <paramref name="usage"/> required of it. Returns null when it builds, or the statuses.
    /// </summary>
    private static string? BuildChain(
        X509Certificate2 leaf, X509Certificate2Collection extra, ModuleSignaturePolicy policy, string usage, DateTimeOffset at)
    {
        using var chain = new X509Chain();
        var options = chain.ChainPolicy;
        options.ApplicationPolicy.Add(new Oid(usage));
        options.VerificationTime = at.UtcDateTime;
        options.VerificationTimeIgnored = false;
        options.VerificationFlags =
            X509VerificationFlags.IgnoreEndRevocationUnknown
            | X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown
            | X509VerificationFlags.IgnoreRootRevocationUnknown;
        // Cached revocation data only: a fetch would be an outbound call the operator never
        // configured, and the service makes none. A revocation Windows already knows about still
        // refuses the module.
        options.RevocationMode = X509RevocationMode.Offline;
        options.RevocationFlag = X509RevocationFlag.ExcludeRoot;
        // For the same reason, never download a missing issuer named in the file's own certificates
        // (#642). A complete signature carries its intermediates; dotnet.exe, the witness, does.
        options.DisableCertificateDownloads = true;

        if (policy.TrustAnchors is { } anchors)
        {
            options.TrustMode = X509ChainTrustMode.CustomRootTrust;
            options.CustomTrustStore.AddRange(anchors);
        }
        else
        {
            options.TrustMode = X509ChainTrustMode.System;
        }

        foreach (var certificate in extra)
            options.ExtraStore.Add(certificate);

        bool built;
        try
        {
            built = chain.Build(leaf);
        }
        catch (CryptographicException ex)
        {
            return ex.Message;
        }

        if (built)
            return null;

        var statuses = chain.ChainStatus.Select(s => s.Status.ToString()).Distinct().ToList();
        return statuses.Count == 0 ? "the chain did not build" : string.Join(", ", statuses);
    }

    /// <summary>The digest algorithm and digest an SpcIndirectDataContent carries.</summary>
    private static (HashAlgorithmName Algorithm, byte[] Digest) ReadIndirectData(byte[] content)
    {
        var reader = new AsnReader(content, AsnEncodingRules.DER);
        var indirect = reader.ReadSequence();
        indirect.ReadSequence(); // SpcAttributeTypeAndOptionalValue: the PE image data, not needed
        var digestInfo = indirect.ReadSequence();
        var algorithm = digestInfo.ReadSequence();
        var oid = algorithm.ReadObjectIdentifier();
        var digest = digestInfo.ReadOctetString();

        // SHA-1 and MD5 are refused as signature digests, whatever Windows itself still accepts:
        // a second preimage on the file's hash is exactly the attack this check exists to stop.
        var name = oid switch
        {
            "2.16.840.1.101.3.4.2.1" => HashAlgorithmName.SHA256,
            "2.16.840.1.101.3.4.2.2" => HashAlgorithmName.SHA384,
            "2.16.840.1.101.3.4.2.3" => HashAlgorithmName.SHA512,
            _ => throw new CryptographicException($"the digest algorithm {oid} is not accepted"),
        };
        return (name, digest);
    }

    /// <summary>The CN and the O of a certificate's subject, each the empty string when absent.</summary>
    private static (string CommonName, string Organisation) ReadSubject(X509Certificate2 certificate)
    {
        string commonName = string.Empty, organisation = string.Empty;
        try
        {
            foreach (var rdn in certificate.SubjectName.EnumerateRelativeDistinguishedNames())
            {
                if (rdn.HasMultipleElements)
                    continue;

                var type = rdn.GetSingleElementType().Value;
                if (string.Equals(type, CommonNameOid, StringComparison.Ordinal))
                    commonName = rdn.GetSingleElementValue() ?? string.Empty;
                else if (string.Equals(type, OrganisationOid, StringComparison.Ordinal))
                    organisation = rdn.GetSingleElementValue() ?? string.Empty;
            }
        }
        catch (AsnContentException)
        {
            // An undecodable subject names nobody.
        }

        return (commonName, organisation);
    }

    /// <summary>
    /// A name as the log may show it: control characters dropped and the length capped, so a
    /// certificate a module carries cannot add a line to the log that names it.
    /// </summary>
    private static string Printable(string value)
    {
        var clean = ModuleBoundary.Clean(value, MaxPublisherLength);
        return string.IsNullOrEmpty(clean) ? "none" : clean;
    }

    /// <summary>
    /// Where the Authenticode hash skips and where the signatures sit, read from a PE image's
    /// headers: the checksum field and the certificate table's directory entry in the optional
    /// header, the end of the headers, the sections, and the certificate table itself.
    /// </summary>
    private sealed class AuthenticodeLayout
    {
        private readonly int _checksumOffset;
        private readonly int _certificateDirectoryOffset;
        private readonly int _sizeOfHeaders;
        private readonly List<(int Start, int Length)> _sections;
        private readonly int _certificateTableOffset;
        private readonly int _certificateTableSize;

        private AuthenticodeLayout(
            int checksumOffset, int certificateDirectoryOffset, int sizeOfHeaders,
            List<(int, int)> sections, int certificateTableOffset, int certificateTableSize)
        {
            _checksumOffset = checksumOffset;
            _certificateDirectoryOffset = certificateDirectoryOffset;
            _sizeOfHeaders = sizeOfHeaders;
            _sections = sections;
            _certificateTableOffset = certificateTableOffset;
            _certificateTableSize = certificateTableSize;
        }

        public static AuthenticodeLayout Read(byte[] image)
        {
            PEHeaders headers;
            using (var pe = new PEReader(new MemoryStream(image, writable: false)))
                headers = pe.PEHeaders;

            var optional = headers.PEHeader ?? throw new BadImageFormatException("the file has no optional header");
            // PEHeader is this API's name for the optional header, and PEHeaderStartOffset is where
            // it starts: after the PE signature and the COFF header, not before them.
            var optionalOffset = headers.PEHeaderStartOffset;
            var checksumOffset = optionalOffset + 64;
            var certificateDirectoryOffset = optionalOffset + (optional.Magic == PEMagic.PE32Plus ? 144 : 128);
            var sizeOfHeaders = optional.SizeOfHeaders;
            if (sizeOfHeaders < certificateDirectoryOffset + 8 || sizeOfHeaders > image.Length)
                throw new BadImageFormatException("the headers are shorter than the optional header");

            var sections = new List<(int, int)>();
            foreach (var section in headers.SectionHeaders)
            {
                if (section.SizeOfRawData == 0)
                    continue;
                var end = (long)section.PointerToRawData + section.SizeOfRawData;
                if (section.PointerToRawData < sizeOfHeaders || end > image.Length)
                    throw new BadImageFormatException($"section {section.Name} lies outside the file");
                sections.Add((section.PointerToRawData, section.SizeOfRawData));
            }
            sections.Sort((a, b) => a.Item1.CompareTo(b.Item1));

            var table = optional.CertificateTableDirectory;
            // For this directory alone the "virtual address" is a file offset.
            var tableOffset = table.RelativeVirtualAddress;
            var tableSize = table.Size;
            if (tableSize != 0)
            {
                // signtool appends the table after every section and nothing follows it, which
                // is the one layout the hash below handles, so anything else is refused.
                if (tableOffset < sizeOfHeaders || (long)tableOffset + tableSize != image.Length)
                    throw new BadImageFormatException("the certificate table is not at the end of the file");
            }

            return new AuthenticodeLayout(checksumOffset, certificateDirectoryOffset, sizeOfHeaders, sections, tableOffset, tableSize);
        }

        /// <summary>Each PKCS#7 blob in the certificate table, in order.</summary>
        public List<byte[]> ReadSignatures(byte[] image)
        {
            var signatures = new List<byte[]>();
            if (_certificateTableSize == 0)
                return signatures;

            var end = _certificateTableOffset + _certificateTableSize;
            var offset = _certificateTableOffset;
            while (offset + 8 <= end)
            {
                var length = BitConverter.ToInt32(image, offset);
                var revision = BitConverter.ToUInt16(image, offset + 4);
                var type = BitConverter.ToUInt16(image, offset + 6);
                if (length < 8 || offset + length > end)
                    throw new InvalidDataException("a certificate table entry runs past the table");

                if (revision == CertificateRevision && type == CertificateTypePkcsSignedData)
                    signatures.Add(image[(offset + 8)..(offset + length)]);

                // Entries are 8 byte aligned.
                offset += (length + 7) & ~7;
            }

            return signatures;
        }

        /// <summary>
        /// The Authenticode hash of <paramref name="image"/>: the headers without the checksum and
        /// the certificate table's directory entry, the sections in file order, and any data after
        /// them except the certificate table.
        /// </summary>
        public byte[] ComputeHash(byte[] image, HashAlgorithmName algorithm)
        {
            using var hash = IncrementalHash.CreateHash(algorithm);
            hash.AppendData(image, 0, _checksumOffset);
            hash.AppendData(image, _checksumOffset + 4, _certificateDirectoryOffset - (_checksumOffset + 4));
            hash.AppendData(image, _certificateDirectoryOffset + 8, _sizeOfHeaders - (_certificateDirectoryOffset + 8));

            var hashed = _sizeOfHeaders;
            foreach (var (start, length) in _sections)
            {
                hash.AppendData(image, start, length);
                hashed += length;
            }

            var extra = image.Length - hashed - _certificateTableSize;
            if (extra > 0)
                hash.AppendData(image, hashed, extra);

            return hash.GetHashAndReset();
        }
    }
}

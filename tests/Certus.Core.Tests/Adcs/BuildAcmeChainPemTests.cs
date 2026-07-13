using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace Certus.Core.Tests.Adcs;

/// <summary>
/// Unit tests for AdcsClient.BuildAcmeChainPem (issue #21 follow-up).
/// The integration test in Certus.Web.Tests stages a pre-built PEM chain into
/// the database and asserts the controller passes it through. That coverage
/// did not exercise the actual chain assembly, which is where the certbot
/// "less than 2 certificates in chain" bug lived: a single tier ADCS root CA
/// produces a PKCS#7 with leaf + self signed root, and the previous code
/// dropped the root before appending it. These tests pin the post fix
/// behaviour: every issuer found by Subject/Issuer DN linkage is appended,
/// including the self signed root, so single tier private CAs return at
/// least two certificates.
/// </summary>
public class BuildAcmeChainPemTests
{
    [Fact]
    public void SingleTier_LeafPlusSelfSignedRoot_ReturnsTwoBlocks()
    {
        using var root = MintSelfSignedCa("CN=Test Root CA");
        using var leaf = MintLeaf("CN=leaf.example.com", root);

        var pkcs7Pem = BuildPkcs7Pem(leaf, root);
        var leafDer = leaf.RawData;

        var chainPem = Certus.Adcs.AdcsClient.BuildAcmeChainPem(leafDer, pkcs7Pem);

        CountBeginCertificates(chainPem).Should().Be(2,
            "RFC 8555 7.4.2 chain must contain leaf + issuer; single tier CA's issuer is its self signed root");
        ChainOrder(chainPem).Should().Equal(
            leaf.SubjectName.Name,
            root.SubjectName.Name);
        AssertEveryBlockCertbotParseable(chainPem, 2);
    }

    [Fact]
    public void TwoTier_LeafIntermediateRoot_ReturnsThreeBlocks()
    {
        using var root = MintSelfSignedCa("CN=Test Root CA");
        using var intermediate = MintSubordinateCa("CN=Test Intermediate CA", root);
        using var leaf = MintLeaf("CN=leaf.example.com", intermediate);

        var pkcs7Pem = BuildPkcs7Pem(leaf, intermediate, root);
        var leafDer = leaf.RawData;

        var chainPem = Certus.Adcs.AdcsClient.BuildAcmeChainPem(leafDer, pkcs7Pem);

        CountBeginCertificates(chainPem).Should().Be(3,
            "two tier CA produces leaf + intermediate + root");
        ChainOrder(chainPem).Should().Equal(
            leaf.SubjectName.Name,
            intermediate.SubjectName.Name,
            root.SubjectName.Name);
        AssertEveryBlockCertbotParseable(chainPem, 3);
    }

    [Fact]
    public void LeafOnlyPkcs7_ReturnsLeafOnly()
    {
        using var root = MintSelfSignedCa("CN=Test Root CA");
        using var leaf = MintLeaf("CN=leaf.example.com", root);

        // PKCS#7 carrying only the leaf, no issuer present in the pool.
        var pkcs7Pem = BuildPkcs7Pem(leaf);
        var leafDer = leaf.RawData;

        var chainPem = Certus.Adcs.AdcsClient.BuildAcmeChainPem(leafDer, pkcs7Pem);

        CountBeginCertificates(chainPem).Should().Be(1,
            "with no issuer in the PKCS#7 pool we degrade gracefully to leaf only");
        AssertEveryBlockCertbotParseable(chainPem, 1);
    }

    [Fact]
    public void StrangerCerts_AreIgnored()
    {
        using var root = MintSelfSignedCa("CN=Test Root CA");
        using var leaf = MintLeaf("CN=leaf.example.com", root);

        // Unrelated chain that does not link to the leaf at all.
        using var strangerRoot = MintSelfSignedCa("CN=Unrelated Root");
        using var strangerLeaf = MintLeaf("CN=stranger.example.com", strangerRoot);

        var pkcs7Pem = BuildPkcs7Pem(leaf, root, strangerRoot, strangerLeaf);
        var leafDer = leaf.RawData;

        var chainPem = Certus.Adcs.AdcsClient.BuildAcmeChainPem(leafDer, pkcs7Pem);

        CountBeginCertificates(chainPem).Should().Be(2,
            "only the leaf and certs reachable by Issuer/Subject linkage are appended");
        ChainOrder(chainPem).Should().Equal(
            leaf.SubjectName.Name,
            root.SubjectName.Name);
        AssertEveryBlockCertbotParseable(chainPem, 2);
    }

    #region Test helpers

    /// <summary>
    /// certbot's regex for splitting a fullchain (acme/crypto_util.py CERT_PEM_REGEX).
    /// It requires a newline after EVERY "-----END CERTIFICATE-----", including the
    /// last block. A chain whose final block lacks a trailing newline yields fewer
    /// matches than it has blocks, which is the "less than 2 certificates in chain"
    /// failure (issues #21, #26). DOTALL in Python maps to Singleline in .NET.
    /// </summary>
    private static readonly Regex CertbotCertRegex = new(
        "-----BEGIN CERTIFICATE-----\r?\n.+?\r?\n-----END CERTIFICATE-----\r?\n",
        RegexOptions.Singleline);

    /// <summary>
    /// Asserts the chain ends in a newline and that certbot's parser finds exactly
    /// <paramref name="expected"/> certificates — i.e. every block is terminated,
    /// not merely present. Guards against a regression that strips the final newline.
    /// </summary>
    private static void AssertEveryBlockCertbotParseable(string chainPem, int expected)
    {
        chainPem.Should().EndWith("\n", "certbot requires a trailing newline after the final certificate block");
        CertbotCertRegex.Matches(chainPem).Count.Should().Be(expected,
            "certbot's CERT_PEM_REGEX must match every block; a missing trailing newline drops the last one");
    }

    private static X509Certificate2 MintSelfSignedCa(string subject)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 2, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));
    }

    private static X509Certificate2 MintSubordinateCa(string subject, X509Certificate2 issuer)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 1, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        var serial = NextSerial();
        using var unsigned = req.Create(issuer, DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(3), serial);
        return unsigned.CopyWithPrivateKey(rsa);
    }

    private static X509Certificate2 MintLeaf(string subject, X509Certificate2 issuer)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        var serial = NextSerial();
        return req.Create(issuer, DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(30), serial);
    }

    private static byte[] NextSerial()
    {
        var b = new byte[8];
        RandomNumberGenerator.Fill(b);
        b[0] &= 0x7F; // keep positive
        if (b[0] == 0) b[0] = 1;
        return b;
    }

    /// <summary>
    /// Builds a degenerate PKCS#7 PEM blob carrying the supplied certificates,
    /// matching the shape returned by ICertRequest::GetCertificate(BASE64HEADER|CHAIN).
    /// </summary>
    private static string BuildPkcs7Pem(params X509Certificate2[] certs)
    {
        var collection = new X509Certificate2Collection();
        foreach (var c in certs) collection.Add(c);
        var der = collection.Export(X509ContentType.Pkcs7)
            ?? throw new InvalidOperationException("Pkcs7 export returned null");
        var b64 = Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks);
        return "-----BEGIN PKCS7-----\n" + b64 + "\n-----END PKCS7-----\n";
    }

    private static int CountBeginCertificates(string pem)
    {
        const string marker = "-----BEGIN CERTIFICATE-----";
        var count = 0;
        var index = 0;
        while ((index = pem.IndexOf(marker, index, StringComparison.Ordinal)) != -1)
        {
            count++;
            index += marker.Length;
        }
        return count;
    }

    /// <summary>
    /// Returns the Subject DN of each certificate block in the chain PEM, in order.
    /// </summary>
    private static List<string> ChainOrder(string pem)
    {
        var subjects = new List<string>();
        const string begin = "-----BEGIN CERTIFICATE-----";
        const string end = "-----END CERTIFICATE-----";
        var cursor = 0;
        while (true)
        {
            var b = pem.IndexOf(begin, cursor, StringComparison.Ordinal);
            if (b < 0) break;
            var e = pem.IndexOf(end, b, StringComparison.Ordinal);
            if (e < 0) break;
            var block = pem.Substring(b, e - b + end.Length);
            using var cert = X509Certificate2.CreateFromPem(block);
            subjects.Add(cert.SubjectName.Name);
            cursor = e + end.Length;
        }
        return subjects;
    }

    #endregion
}

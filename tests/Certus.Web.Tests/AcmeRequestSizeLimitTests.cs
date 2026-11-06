using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Models;
using Certus.Core.Acme.Services;
using Certus.Web.Controllers.Acme;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Http.Metadata;
using Microsoft.AspNetCore.Mvc;
using Xunit.Abstractions;

namespace Certus.Web.Tests;

/// <summary>
/// The request body cap on the ACME surface (issue #300), as far as it can be proved without a
/// server. Every endpoint but the challenge used to fall back to Kestrel's 30 MB default, and each
/// one reads its whole body and decodes the JWS payload before acting on it.
///
/// <para>Three things are pinned here. The attribute is where MVC will find it on every ACME
/// controller, with the challenge's larger cap the only override. The cap holds the largest body
/// each endpoint honestly receives, derived from the same constants the endpoints enforce, so a
/// cap lowered past them fails here with the reason in the message. And a body the server refuses
/// to read is answered as an ACME problem document carrying the status the server chose.</para>
///
/// <para>TestServer does not enforce <c>[RequestSizeLimit]</c>, which is a Kestrel feature, so
/// nothing in this class proves Kestrel acts on the attribute. AcmeRequestSizeLimitKestrelTests
/// does, against a real Kestrel on a loopback port.</para>
/// </summary>
public class AcmeRequestSizeLimitTests
{
    // A generous origin for the size arithmetic: the longest DNS host, the highest port, and the
    // longest name an AD certificate template can carry. Real ones are far shorter, and the URL
    // appears twice in a kid authenticated header (kid and url).
    private static readonly string LongOrigin = "https://" + new string('h', 253) + ":65535";
    private static readonly string LongTemplate = new('t', 64);
    private static readonly string LongId = new('i', 64);
    private static readonly string Nonce = new('n', 64);

    // One RSA 4096 key plays every role the arithmetic needs (account key, certificate key, and
    // issuer key): only its size matters, and generating one is slow enough to share.
    private static readonly Lazy<RSA> Rsa4096 = new(() => RSA.Create(4096));

    // The sizes go to the test output as well as into the failure messages, so the numbers the
    // cap's doc comment quotes can be read back off any run.
    private readonly ITestOutputHelper _output;

    public AcmeRequestSizeLimitTests(ITestOutputHelper output) => _output = output;

    // ---- where MVC finds the cap ----

    [Fact]
    public void EveryAcmeController_InheritsTheCap()
    {
        var controllers = AcmeControllers();
        controllers.Should().Contain([typeof(AuthorizationController), typeof(AccountController)],
            "these are the two the issue names");

        foreach (var controller in controllers)
        {
            // inherit: true is how MVC reads controller attributes, and it honours the
            // attribute's own Inherited flag, so this fails if the base class's attribute stops
            // reaching the controllers that derive from it.
            IRequestSizeLimitMetadata? limit =
                controller.GetCustomAttribute<RequestSizeLimitAttribute>(inherit: true);
            limit.Should().NotBeNull($"{controller.Name} must be size capped");
            limit!.MaxRequestBodySize.Should().Be(AcmeControllerBase.MaxRequestBytes, controller.Name);
        }
    }

    [Fact]
    public void TheChallenge_IsTheOnlyAction_ThatOverridesTheCap_AndItsCapIsLarger()
    {
        // An override is a decision about one endpoint's honest maximum. The challenge is the
        // only one with a reason to differ (a device attestation object), so a second override,
        // or anything that turns the cap off, should be made deliberately and recorded here.
        var overrides = AcmeControllers()
            .SelectMany(controller => controller.GetMethods(
                BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            .Where(action => action.IsDefined(typeof(RequestSizeLimitAttribute)))
            .Select(action => $"{action.DeclaringType!.Name}.{action.Name}");

        overrides.Should().Equal($"{nameof(ChallengeController)}.{nameof(ChallengeController.RespondToChallenge)}");
        ChallengeCap().Should().BeGreaterThan(AcmeControllerBase.MaxRequestBytes);

        foreach (var controller in AcmeControllers())
        {
            controller.IsDefined(typeof(DisableRequestSizeLimitAttribute), inherit: true)
                .Should().BeFalse(controller.Name);
            controller.GetMethods().Where(m => m.IsDefined(typeof(DisableRequestSizeLimitAttribute)))
                .Should().BeEmpty(controller.Name);
        }
    }

    // ---- the cap holds every honest body ----

    [Fact]
    public void TheLargestAccountUpdate_FitsUnderTheCap()
    {
        // The account endpoint stores at most MaxContactEntries contacts of MaxContactLength
        // characters each. A character outside ASCII leaves the default JSON encoder as a six
        // byte escape, which is the most bytes any one character can cost.
        var contact = Enumerable.Range(0, AccountService.MaxContactEntries)
            .Select(_ => new string((char)0x4E2D, AccountService.MaxContactLength))
            .ToArray();
        AccountService.ValidateContacts(contact, out _).Should().BeTrue("the payload must be one the endpoint accepts");

        var payload = JsonSerializer.Serialize(new { contact });
        payload.Length.Should().BeGreaterThanOrEqualTo(
            AccountService.MaxContactEntries * AccountService.MaxContactLength * 6,
            "every character must be paying the escape, or this is not the worst case");

        var size = KidJwsSize($"/acme/{LongTemplate}/acct/{LongId}", payload);
        _output.WriteLine($"Largest account update: {size} bytes");

        size.Should().BeLessThan(AcmeControllerBase.MaxRequestBytes,
            $"the largest account update is {size} bytes of JWS");
    }

    [Fact]
    public void TheLargestFinalize_FitsUnderTheCap()
    {
        // No product setting bounds the names in an order, so the yardstick is the per
        // certificate ceiling Let's Encrypt applies, 100 names, each at the 253 character DNS
        // maximum, with an RSA 4096 key in the CSR as well as on the account.
        var key = Rsa4096.Value;
        var request = new CertificateRequest(
            "CN=" + new string('c', 64), key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(HundredLongNames());
        var csr = request.CreateSigningRequest();

        var payload = $$"""{"csr":"{{JwsService.Base64UrlEncode(csr)}}"}""";
        var size = KidJwsSize($"/acme/{LongTemplate}/order/{LongId}/finalize", payload);
        _output.WriteLine($"Largest finalize: {size} bytes");

        size.Should().BeLessThan(AcmeControllerBase.MaxRequestBytes,
            $"a finalize carrying 100 names of 253 characters is {size} bytes of JWS");
    }

    [Fact]
    public void TheLargestRevocation_FitsUnderTheCap()
    {
        // The certificate a finalize like the one above produces, carrying what an ADCS CA adds
        // to it, revoked by its own key (the jwk form, whose header carries the whole public key).
        var key = Rsa4096.Value;
        var request = new CertificateRequest(
            "CN=" + new string('c', 64), key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(HundredLongNames());
        foreach (var extension in AdcsShapedExtensions(key))
            request.CertificateExtensions.Add(extension);

        var issuer = new X500DistinguishedName("CN=" + new string('a', 64) + ", DC=example, DC=local");
        using var certificate = request.Create(
            issuer,
            X509SignatureGenerator.CreateForRSA(key, RSASignaturePadding.Pkcs1),
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(1),
            RandomNumberGenerator.GetBytes(19));

        var payload = $$"""{"certificate":"{{JwsService.Base64UrlEncode(certificate.RawData)}}","reason":4}""";
        var p = key.ExportParameters(false);
        var jwk = $$"""{"kty":"RSA","n":"{{JwsService.Base64UrlEncode(p.Modulus!)}}","e":"{{JwsService.Base64UrlEncode(p.Exponent!)}}"}""";
        var header = $$"""{"alg":"RS256","jwk":{{jwk}},"nonce":"{{Nonce}}","url":"{{LongOrigin}}/acme/{{LongTemplate}}/revoke-cert"}""";
        var size = JwsSize(header, payload);
        _output.WriteLine($"Largest revocation: {size} bytes");

        size.Should().BeLessThan(AcmeControllerBase.MaxRequestBytes,
            $"revoking a certificate carrying 100 names of 253 characters is {size} bytes of JWS");
    }

    [Fact]
    public void TheLargestAttestation_FitsUnderTheChallengeCap()
    {
        // The challenge keeps its own cap because of this body: the largest attObj the action
        // itself admits, encoded a second time by the JWS.
        var field = typeof(ChallengeController)
            .GetField("MaxAttestationObjectChars", BindingFlags.NonPublic | BindingFlags.Static);
        field.Should().NotBeNull(
            "this test sizes the challenge cap from ChallengeController's attObj limit; " +
            "if that constant was renamed, follow it here");
        var maxChars = (int)field!.GetRawConstantValue()!;

        var payload = JsonSerializer.Serialize(new { attObj = new string('A', maxChars) });
        var size = KidJwsSize($"/acme/{LongTemplate}/chall/{LongId}", payload);
        _output.WriteLine($"Largest attestation: {size} bytes");

        size.Should().BeGreaterThan(AcmeControllerBase.MaxRequestBytes,
            "otherwise the challenge would not need a cap of its own");
        ((long)size).Should().BeLessThan(ChallengeCap(),
            $"the largest attestation the challenge admits is {size} bytes of JWS");
    }

    // ---- what a body the server will not read is answered with ----

    [Fact]
    public async Task ABodyOverTheLimit_IsAnswered413_NamingTheLimitThatApplied()
    {
        var context = ContextWhoseBodyThrows(StatusCodes.Status413PayloadTooLarge);
        context.Features.Set<IHttpMaxRequestBodySizeFeature>(new FixedLimit(AcmeControllerBase.MaxRequestBytes));

        var (_, error) = await new BodyReader(context).ReadAsync();

        var problem = AssertProblem(error, StatusCodes.Status413PayloadTooLarge);
        problem.Detail.Should().Contain(AcmeControllerBase.MaxRequestBytes.ToString());
    }

    [Fact]
    public async Task ABodyOverTheLimit_WithNoLimitToName_IsStillAnswered413()
    {
        var (_, error) = await new BodyReader(
            ContextWhoseBodyThrows(StatusCodes.Status413PayloadTooLarge)).ReadAsync();

        AssertProblem(error, StatusCodes.Status413PayloadTooLarge)
            .Detail.Should().Be("The request body is larger than this endpoint accepts.");
    }

    [Theory]
    [InlineData(StatusCodes.Status400BadRequest)]     // a malformed chunked body
    [InlineData(StatusCodes.Status408RequestTimeout)] // a body sent too slowly
    public async Task ABodyThatCannotBeRead_ForAnotherReason_KeepsItsOwnStatus(int status)
    {
        // The same exception type carries all three, and only the 413 is about size, so the
        // others must not be told their body was too large.
        var (_, error) = await new BodyReader(ContextWhoseBodyThrows(status)).ReadAsync();

        AssertProblem(error, status).Detail.Should().Be("The request body could not be read.");
    }

    [Fact]
    public async Task ABodyThatReads_IsReturnedWhole()
    {
        var context = new DefaultHttpContext();
        context.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes("""{"protected":"x"}"""));

        var (body, error) = await new BodyReader(context).ReadAsync();

        error.Should().BeNull();
        body.Should().Be("""{"protected":"x"}""");
    }

    // ---- helpers ----

    private static List<Type> AcmeControllers() =>
        typeof(AcmeControllerBase).Assembly.GetTypes()
            .Where(type => type.IsSubclassOf(typeof(AcmeControllerBase)) && !type.IsAbstract)
            .ToList();

    private static long ChallengeCap()
    {
        IRequestSizeLimitMetadata limit = typeof(ChallengeController)
            .GetMethod(nameof(ChallengeController.RespondToChallenge))!
            .GetCustomAttribute<RequestSizeLimitAttribute>()!;
        return limit.MaxRequestBodySize!.Value;
    }

    /// <summary>100 DNS names of 253 characters each, four labels apiece, every one distinct.</summary>
    private static X509Extension HundredLongNames()
    {
        var san = new SubjectAlternativeNameBuilder();
        for (var i = 0; i < 100; i++)
        {
            var name = $"{i:D3}{new string('a', 60)}.{new string('b', 63)}.{new string('c', 63)}.{new string('d', 61)}";
            name.Length.Should().Be(253);
            san.AddDnsName(name);
        }

        return san.Build();
    }

    /// <summary>
    /// Stands in for what an ADCS CA writes into a leaf beside the requester's names: key
    /// identifiers, an LDAP and an HTTP distribution point and issuer location in the shapes an
    /// enterprise CA publishes, the key usages, and the two template extensions, sized like them.
    /// </summary>
    private static IEnumerable<X509Extension> AdcsShapedExtensions(RSA key)
    {
        var ca = new string('a', 64);
        var host = new string('h', 63) + ".example.local";
        var ldap = $"ldap:///CN={ca},CN={host},CN=CDP,CN=Public%20Key%20Services,CN=Services," +
                   "CN=Configuration,DC=example,DC=local?certificateRevocationList?base?objectClass=cRLDistributionPoint";
        var aia = $"ldap:///CN={ca},CN=AIA,CN=Public%20Key%20Services,CN=Services," +
                  "CN=Configuration,DC=example,DC=local?cACertificate?base?objectClass=certificationAuthority";

        var ski = new X509SubjectKeyIdentifierExtension(new PublicKey(key), false);
        yield return ski;
        yield return X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(ski);
        yield return CertificateRevocationListBuilder.BuildCrlDistributionPointExtension(
            [ldap, $"http://{host}/CertEnroll/{ca}.crl"]);
        yield return new X509AuthorityInformationAccessExtension(
            [$"http://{host}/ocsp"], [aia, $"http://{host}/CertEnroll/{host}_{ca}.crt"]);
        yield return new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true);
        yield return new X509EnhancedKeyUsageExtension(
            new OidCollection { new Oid("1.3.6.1.5.5.7.3.1"), new Oid("1.3.6.1.5.5.7.3.2") }, false);
        yield return new X509Extension("1.3.6.1.4.1.311.21.7", new byte[48], false);  // template information
        yield return new X509Extension("1.3.6.1.4.1.311.21.10", new byte[32], false); // application policies
    }

    /// <summary>The byte length of a flattened JWS authenticated by kid, posted to <paramref name="path"/>.</summary>
    private static int KidJwsSize(string path, string payload) =>
        JwsSize(
            $$"""{"alg":"RS256","kid":"{{LongOrigin}}/acme/{{LongTemplate}}/acct/{{LongId}}","nonce":"{{Nonce}}","url":"{{LongOrigin}}{{path}}"}""",
            payload);

    private static int JwsSize(string header, string payload)
    {
        var protectedB64 = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(header));
        var payloadB64 = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(payload));
        var signature = Rsa4096.Value.SignData(
            Encoding.ASCII.GetBytes($"{protectedB64}.{payloadB64}"),
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var body = JsonSerializer.Serialize(new JwsFlattenedRequest
        {
            Protected = protectedB64,
            Payload = payloadB64,
            Signature = JwsService.Base64UrlEncode(signature),
        });
        return Encoding.UTF8.GetByteCount(body);
    }

    private static DefaultHttpContext ContextWhoseBodyThrows(int status)
    {
        var context = new DefaultHttpContext();
        context.Request.Body = new ThrowingStream(status);
        return context;
    }

    private static AcmeError AssertProblem(IActionResult? error, int status)
    {
        var result = error.Should().BeOfType<ObjectResult>().Subject;
        result.StatusCode.Should().Be(status);
        result.ContentTypes.Should().Contain("application/problem+json");

        var problem = result.Value.Should().BeOfType<AcmeError>().Subject;
        problem.Type.Should().Be(AcmeErrorType.Malformed);
        problem.Status.Should().Be(status);
        return problem;
    }

    /// <summary>The smallest ACME controller there is, to reach the protected body reader.</summary>
    [NonController]
    private sealed class BodyReader : AcmeControllerBase
    {
        public BodyReader(HttpContext context) =>
            ControllerContext = new ControllerContext { HttpContext = context };

        public Task<(string Body, IActionResult? Error)> ReadAsync() =>
            ReadRequestBodyAsync(CancellationToken.None);
    }

    /// <summary>A body stream that refuses every read the way Kestrel's does.</summary>
    private sealed class ThrowingStream(int status) : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) => throw Refusal();

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            throw Refusal();

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            throw Refusal();

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        private BadHttpRequestException Refusal() => new("The server refused to read the body.", status);
    }

    private sealed class FixedLimit(long limit) : IHttpMaxRequestBodySizeFeature
    {
        public bool IsReadOnly => false;
        public long? MaxRequestBodySize { get; set; } = limit;
    }
}

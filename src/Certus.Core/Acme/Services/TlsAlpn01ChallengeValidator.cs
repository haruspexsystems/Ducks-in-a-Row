using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.Logging;

namespace Certus.Core.Acme.Services;

/// <summary>
/// Validates TLS-ALPN-01 challenges by connecting to the domain on port 443
/// with the "acme-tls/1" ALPN protocol and verifying the self signed certificate
/// contains the acmeIdentifier extension with the correct key authorization digest.
/// RFC 8737 (TLS-ALPN-01 Challenge)
///
/// The server must present a self signed certificate with:
/// - SAN matching the domain
/// - acmeIdentifier extension (OID 1.3.6.1.5.5.7.1.31) containing SHA-256(keyAuth)
/// - The negotiated ALPN protocol must be "acme-tls/1"
/// </summary>
public sealed class TlsAlpn01ChallengeValidator : IChallengeValidator
{
    /// <summary>
    /// OID for the acmeIdentifier extension per RFC 8737 §3.
    /// </summary>
    public const string AcmeIdentifierOid = "1.3.6.1.5.5.7.1.31";

    private readonly ILogger<TlsAlpn01ChallengeValidator> _logger;
    private readonly AddressGuard _addressGuard;
    private readonly TimeSpan _timeout;

    public TlsAlpn01ChallengeValidator(
        ILogger<TlsAlpn01ChallengeValidator> logger, AddressGuard addressGuard)
        : this(logger, addressGuard, TimeSpan.FromSeconds(10))
    {
    }

    /// <summary>
    /// Constructor with configurable timeout (for testing).
    /// </summary>
    public TlsAlpn01ChallengeValidator(
        ILogger<TlsAlpn01ChallengeValidator> logger, AddressGuard addressGuard, TimeSpan timeout)
    {
        _logger = logger;
        _addressGuard = addressGuard;
        _timeout = timeout;
    }

    public string ChallengeType => "tls-alpn-01";

    public async Task<ChallengeValidationResult> ValidateAsync(
        ChallengeValidationContext context,
        CancellationToken cancellationToken = default)
    {
        var domain = context.IdentifierValue;
        var token = context.Token;
        var accountThumbprint = context.AccountThumbprint;

        // Expected: SHA-256(token.thumbprint), raw bytes (32 bytes)
        var keyAuth = $"{token}.{accountThumbprint}";
        var expectedDigest = SHA256.HashData(Encoding.UTF8.GetBytes(keyAuth));

        try
        {
            _logger.LogDebug("TLS-ALPN-01 validation: connecting to {Domain}:443", domain);

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(_timeout);

            // Vet the resolved address before connecting (server side request forgery guard).
            // Connecting to the vetted IP, with TargetHost still set to the domain for SNI,
            // also defeats DNS rebinding between order creation and validation.
            var address = await _addressGuard.ResolveAndVetAsync(domain, cts.Token);

            using var tcpClient = new TcpClient();
            await tcpClient.ConnectAsync(address, 443, cts.Token);

            var sslOptions = new SslClientAuthenticationOptions
            {
                TargetHost = domain,
                ApplicationProtocols = new List<SslApplicationProtocol>
                {
                    new("acme-tls/1")
                },
                // We accept self signed certs — the validation is done by checking
                // the acmeIdentifier extension, not the certificate chain
                RemoteCertificateValidationCallback = (_, _, _, _) => true
            };

            using var sslStream = new SslStream(tcpClient.GetStream());
            await sslStream.AuthenticateAsClientAsync(sslOptions, cts.Token);

            // 1. Check ALPN was negotiated
            if (sslStream.NegotiatedApplicationProtocol !=
                new SslApplicationProtocol("acme-tls/1"))
            {
                _logger.LogWarning(
                    "TLS-ALPN-01 validation failed for {Domain}: ALPN not negotiated as acme-tls/1",
                    domain);
                return ChallengeValidationResult.Invalid(
                    "TLS-ALPN-01: server did not negotiate acme-tls/1 ALPN protocol.");
            }

            // 2. Get the peer certificate
            using var remoteCert = sslStream.RemoteCertificate;
            if (remoteCert == null)
            {
                return ChallengeValidationResult.Invalid(
                    "TLS-ALPN-01: server did not present a certificate.");
            }

            using var x509 = new X509Certificate2(remoteCert);

            // 3. Verify the certificate has a SAN matching the domain
            var sanExtension = x509.Extensions["2.5.29.17"]; // SAN OID
            if (sanExtension == null)
            {
                return ChallengeValidationResult.Invalid(
                    "TLS-ALPN-01: certificate does not contain a SAN extension.");
            }

            // Parse SAN to check for matching DNS name
            var sanExt = (X509SubjectAlternativeNameExtension)sanExtension;
            var dnsNames = sanExt.EnumerateDnsNames().ToList();
            if (!dnsNames.Any(d => d.Equals(domain, StringComparison.OrdinalIgnoreCase)))
            {
                _logger.LogWarning(
                    "TLS-ALPN-01 validation failed for {Domain}: SAN does not contain the domain",
                    domain);
                return ChallengeValidationResult.Invalid(
                    "TLS-ALPN-01: certificate SAN does not match the domain.");
            }

            // 4. Check for the acmeIdentifier extension
            var acmeExt = x509.Extensions[AcmeIdentifierOid];
            if (acmeExt == null)
            {
                _logger.LogWarning(
                    "TLS-ALPN-01 validation failed for {Domain}: certificate missing acmeIdentifier extension",
                    domain);
                return ChallengeValidationResult.Invalid(
                    "TLS-ALPN-01: certificate does not contain the acmeIdentifier extension.");
            }

            // 5. The acmeIdentifier extension must be marked critical
            if (!acmeExt.Critical)
            {
                _logger.LogWarning(
                    "TLS-ALPN-01 validation failed for {Domain}: acmeIdentifier extension is not critical",
                    domain);
                return ChallengeValidationResult.Invalid(
                    "TLS-ALPN-01: acmeIdentifier extension must be marked critical.");
            }

            // 6. Verify extension value: DER encoded ASN.1 OCTET STRING containing the hash
            // The raw data is: ASN.1 OCTET STRING tag (04) + length (20) + 32 bytes SHA-256 hash
            var extBytes = acmeExt.RawData;
            var actualDigest = ExtractDigestFromAcmeIdentifierExtension(extBytes);

            if (actualDigest == null || !actualDigest.SequenceEqual(expectedDigest))
            {
                _logger.LogWarning(
                    "TLS-ALPN-01 validation failed for {Domain}: acmeIdentifier digest mismatch",
                    domain);
                return ChallengeValidationResult.Invalid(
                    "TLS-ALPN-01: acmeIdentifier extension value does not match expected digest.");
            }

            _logger.LogInformation("TLS-ALPN-01 validation succeeded for {Domain}", domain);
            return ChallengeValidationResult.Success();
        }
        catch (AddressBlockedException)
        {
            // The configured egress policy blocked the resolved address (server side request
            // forgery guard). Permanent rejection, not a transient blip.
            _logger.LogWarning(
                "TLS-ALPN-01 validation rejected for {Domain}: target resolves to a blocked address",
                domain);
            return ChallengeValidationResult.Invalid(
                $"TLS-ALPN-01 target {domain} resolves to an address that is not permitted.");
        }
        catch (SocketException ex)
        {
            _logger.LogWarning(ex,
                "TLS-ALPN-01 could not reach {Domain} (transient)", domain);
            return ChallengeValidationResult.TransientFailure(
                $"Could not connect to {domain}:443 for TLS-ALPN-01 validation: {ex.Message}");
        }
        catch (AuthenticationException ex)
        {
            _logger.LogWarning(ex,
                "TLS-ALPN-01 TLS handshake error for {Domain} (transient)", domain);
            return ChallengeValidationResult.TransientFailure(
                $"TLS handshake failed with {domain}: {ex.Message}");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            _logger.LogWarning("TLS-ALPN-01 validation timed out for {Domain} (transient)", domain);
            return ChallengeValidationResult.TransientFailure(
                $"TLS-ALPN-01 validation timed out connecting to {domain}.");
        }
    }

    /// <summary>
    /// Extracts the SHA-256 digest from the acmeIdentifier extension raw data.
    /// Per RFC 8737 §3, the extension value is an ASN.1 OCTET STRING
    /// containing the 32-byte SHA-256 hash of the key authorization.
    /// The raw data is the DER encoding of this OCTET STRING.
    /// </summary>
    public static byte[]? ExtractDigestFromAcmeIdentifierExtension(byte[] rawData)
    {
        // The raw data should be a DER OCTET STRING:
        // Tag: 0x04, Length: 0x20 (32), then 32 bytes of hash
        if (rawData.Length >= 34 && rawData[0] == 0x04 && rawData[1] == 0x20)
        {
            return rawData[2..34];
        }

        // Fallback: if the raw data IS the 32 bytes directly (no ASN.1 wrapper)
        if (rawData.Length == 32)
        {
            return rawData;
        }

        return null;
    }
}

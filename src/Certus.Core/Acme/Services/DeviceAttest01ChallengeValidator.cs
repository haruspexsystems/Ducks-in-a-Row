using System.Text.Json;
using Certus.Core.Acme.Attestation;
using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Models;
using Microsoft.Extensions.Logging;

namespace Certus.Core.Acme.Services;

/// <summary>
/// Validates device-attest-01 challenges (draft-ietf-acme-device-attest-08).
/// Unlike the network challenge types this validator makes no outbound
/// request: the client already POSTed its attestation object to the
/// challenge URL, and validation is pure verification of that payload plus
/// a re-check of the device gate. Every failure is final (never transient)
/// with the draft's badAttestationStatement error type: a wrong attestation
/// stays wrong on retry, and Apple rate limits fresh attestations, so the
/// server must never sit in a retry loop hoping one changes.
/// </summary>
public sealed class DeviceAttest01ChallengeValidator : IChallengeValidator
{
    /// <summary>The challenge type string, shared with the worker's audit branch.</summary>
    public const string TypeName = "device-attest-01";

    private readonly IEnumerable<IAttestationFormatVerifier> _verifiers;
    private readonly AttestationTrustAnchorStore _anchorStore;
    private readonly DeviceAttestationPolicyService _policyService;
    private readonly ILogger<DeviceAttest01ChallengeValidator> _logger;

    public DeviceAttest01ChallengeValidator(
        IEnumerable<IAttestationFormatVerifier> verifiers,
        AttestationTrustAnchorStore anchorStore,
        DeviceAttestationPolicyService policyService,
        ILogger<DeviceAttest01ChallengeValidator> logger)
    {
        _verifiers = verifiers;
        _anchorStore = anchorStore;
        _policyService = policyService;
        _logger = logger;
    }

    public string ChallengeType => TypeName;

    public async Task<ChallengeValidationResult> ValidateAsync(
        ChallengeValidationContext context,
        CancellationToken cancellationToken = default)
    {
        var identifier = context.IdentifierValue;

        if (context.IdentifierType != AcmeIdentifierTypes.PermanentIdentifier)
            return Fail(identifier,
                $"device-attest-01 does not apply to \"{context.IdentifierType}\" identifiers.");

        if (string.IsNullOrEmpty(context.ChallengePayload))
            return Fail(identifier, "No attestation object was submitted for the challenge.");

        byte[] attestationObject;
        try
        {
            attestationObject = JwsService.Base64UrlDecode(context.ChallengePayload);
        }
        catch (FormatException)
        {
            return Fail(identifier, "The attestation object is not valid base64url.");
        }

        AttestationEnvelope envelope;
        try
        {
            envelope = AttestationEnvelope.Parse(attestationObject);
        }
        catch (AttestationParseException ex)
        {
            return Fail(identifier, ex.Message);
        }

        var verifier = _verifiers.FirstOrDefault(v => v.Format == envelope.Format);
        if (verifier is null)
            return Fail(identifier,
                $"The attestation format \"{envelope.Format}\" is not supported.");

        var anchors = await _anchorStore.GetEnabledAnchorsAsync(envelope.Format, cancellationToken);
        try
        {
            var verification = await verifier.VerifyAsync(
                new AttestationContext(envelope, context.Token, identifier, anchors),
                cancellationToken);

            if (!verification.IsValid)
                return Fail(identifier,
                    verification.ErrorDetail ?? "The attestation did not verify.");

            // Belt and braces on the verifier contract: a valid result must carry
            // the matched identifier and the attested key, octet exact.
            if (!string.Equals(verification.AttestedIdentifierValue, identifier, StringComparison.Ordinal))
                return Fail(identifier,
                    "The attested device identifier does not match the order identifier.");
            if (verification.AttestedSpkiDer is not { Length: > 0 })
                return Fail(identifier, "The attestation did not yield the attested public key.");

            // Re-check the device gate mid flight: the profile may have been
            // disabled, or the device delisted, between newOrder and this sweep.
            // Fail closed exactly as newOrder would.
            var outcome = await _policyService.CheckAsync(
                context.TemplateId, identifier, cancellationToken);
            if (outcome is not (DeviceAttestationPolicyOutcome.AllowedOpen
                or DeviceAttestationPolicyOutcome.AllowedListed))
                return Fail(identifier,
                    "The device is not permitted by the current device attestation policy.");

            _logger.LogInformation(
                "device-attest-01 validation succeeded for {Identifier} (format {Format}, gate {Outcome})",
                identifier, envelope.Format, outcome);

            return ChallengeValidationResult.Success(new AttestedDeviceData(
                Convert.ToBase64String(verification.AttestedSpkiDer),
                envelope.Format,
                verification.AttestedProperties is { Count: > 0 }
                    ? JsonSerializer.Serialize(verification.AttestedProperties)
                    : null));
        }
        finally
        {
            foreach (var anchor in anchors)
                anchor.Dispose();
        }
    }

    private ChallengeValidationResult Fail(string identifier, string detail)
    {
        _logger.LogWarning(
            "device-attest-01 validation failed for {Identifier}: {Detail}", identifier, detail);
        return ChallengeValidationResult.Invalid(detail, AcmeErrorType.BadAttestationStatement);
    }
}

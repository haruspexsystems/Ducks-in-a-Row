using System.Net;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certus.Core.Adcs;
using Microsoft.Extensions.Logging;

namespace Certus.Core.Setup;

/// <summary>
/// Enrolls a TLS certificate for the Ducks in a Row server itself from the
/// connected CA, using the template the wizard selected. This is also the
/// live end to end test of that template: the service submits every ACME
/// order to the CA as its own computer account, so a certificate issued here
/// proves Request Certificates on the CA, the policy module's acceptance, and
/// Enroll on this one template. It proves nothing about any other template
/// exposed over ACME; the service rights check (issue #440) reads those, and
/// only an enrolment from each proves it.
///
/// The submission goes through <see cref="IAdcsClientFactory"/> with the
/// candidate connection string, like every other wizard probe — during setup
/// the DI bound client is the unconfigured client and cannot reach the CA.
///
/// Two CA exceptions propagate to the caller rather than folding into a
/// <see cref="TlsEnrollmentResult"/>: <see cref="Adcs.CaUnavailableException"/>
/// and <see cref="Adcs.CaAccessDeniedException"/>. Both controllers and the
/// automatic renewal service build their 503 and their alert on them reaching
/// them. They travel together and a caller must handle both, or a permissions
/// failure faults where an outage would have been answered (issue #336). A CA
/// that denies the request through its policy module is a different thing and
/// does not throw at all: it arrives as <see cref="SubmitStatus.Denied"/> and
/// becomes <see cref="TlsEnrollmentResult.Denied"/> below.
/// </summary>
public sealed class TlsCertificateEnroller
{
    /// <summary>
    /// The RSA floor when the template's minimum could not be read, or asks
    /// for less: 2048 is the common template minimum and the smallest size
    /// current ADCS policy modules accept.
    /// </summary>
    private const int MinimumRsaKeySizeBits = 2048;

    private readonly IAdcsClientFactory _clientFactory;
    private readonly IHttpsCertificateStore _certificateStore;
    private readonly ILogger<TlsCertificateEnroller> _logger;

    public TlsCertificateEnroller(
        IAdcsClientFactory clientFactory,
        IHttpsCertificateStore certificateStore,
        ILogger<TlsCertificateEnroller> logger)
    {
        _clientFactory = clientFactory;
        _certificateStore = certificateStore;
        _logger = logger;
    }

    /// <summary>
    /// Enroll a certificate for the host in <paramref name="externalUrl"/>
    /// and install it into the HTTPS certificate store. Nothing here writes
    /// configuration or restarts the service; the caller decides that based
    /// on the coverage flags in the result.
    /// </summary>
    /// <param name="caConnectionString">The candidate CA from the wizard state.</param>
    /// <param name="templateName">
    /// The configured template, in either form. ADCS matches a request against
    /// the programmatic name (the AD <c>cn</c>) alone, so this is resolved
    /// against the CA's own published list before anything is submitted; see
    /// <see cref="ResolveTemplateAsync"/>.
    /// </param>
    /// <param name="externalUrl">The external URL whose host goes into CN and SAN.</param>
    /// <param name="currentHost">
    /// The host the admin's browser is on (the request Host header), so the
    /// caller can tell whether that browsing session survives the restart.
    /// </param>
    public async Task<TlsEnrollmentResult> EnrollAsync(
        string caConnectionString,
        string templateName,
        string externalUrl,
        string? currentHost,
        CancellationToken cancellationToken = default)
    {
        if (!Uri.TryCreate(externalUrl, UriKind.Absolute, out var uri) || string.IsNullOrEmpty(uri.Host))
        {
            return TlsEnrollmentResult.Failed("The external URL is not a valid absolute URL.");
        }

        // The refusals below name the configured template back to the caller,
        // and that text reaches a log line and an HTTP response body. Guard the
        // name here rather than trusting each caller to have done it, so this
        // class is safe to reach with any string (issue #175). Every current
        // caller already validates or resolves upstream, so nothing changes for
        // them; what changes is that a future one cannot forget.
        if (!AdcsRequestAttributes.TryValidateTemplateName(templateName, out var templateError))
        {
            return TlsEnrollmentResult.Failed(templateError!);
        }

        var host = uri.Host;

        var client = _clientFactory.Create(caConnectionString);
        try
        {
            var lookup = await ResolveTemplateAsync(client, templateName, cancellationToken);

            if (lookup.ListRead && lookup.CanonicalName is null)
            {
                // The CA answered with its list and this template is not on it,
                // so submitting would only earn the policy module's opaque
                // 0x80094800. Say which name failed and why, because the usual
                // cause is a display name in the configuration (issue #194).
                _logger.LogWarning(
                    "The CA at {Config} does not publish a certificate template named {Template}",
                    caConnectionString, templateName);
                return TlsEnrollmentResult.Failed(
                    $"The CA does not publish a certificate template named {templateName}. " +
                    $"ADCS matches a request against the template's programmatic name (its AD " +
                    $"cn), which has no spaces, and not against its display name. Pick the " +
                    $"template again so the published name is recorded.");
            }

            // Unmapped is not the same as unpublished: a list that could not be
            // read tells us nothing, so fall back to the configured value and
            // let the CA answer, exactly as this method behaved before the
            // resolution existed. A transient AD or CA failure must not break
            // an install that already records the programmatic name.
            var submitTemplate = lookup.CanonicalName ?? templateName;
            if (!string.Equals(submitTemplate, templateName, StringComparison.Ordinal))
            {
                _logger.LogInformation(
                    "Configured template {Configured} resolved to the CA's published name {Published}",
                    templateName, submitTemplate);
            }

            AsymmetricAlgorithm key;
            try
            {
                key = CreateKey(lookup.KeyAlgorithm, lookup.MinimalKeySize);

                // The enrollment goes ahead, so this is a log line rather than a
                // failure, but the template is still almost certainly wrong for
                // a TLS purpose and only an administrator can fix that. See
                // CreateKey's remarks for why the substitution itself is sound.
                if (IsEcdhAlgorithm(lookup.KeyAlgorithm))
                {
                    _logger.LogWarning(
                        "Template {Template} records {Algorithm}, an encryption only algorithm. Enrolling " +
                        "with an ECDSA key on the same curve, because a PKCS#10 is self signed and cannot " +
                        "carry an ECDH key at all. ADCS records this when the template's Request Handling " +
                        "tab Purpose is \"Signature and encryption\"; set it to \"Signature\" and the " +
                        "template will record ECDSA instead",
                        submitTemplate, lookup.KeyAlgorithm);
                }
            }
            catch (NotSupportedException ex)
            {
                // The template names an algorithm we cannot generate. Refuse
                // here rather than submit an RSA request the CA will either
                // deny opaquely or, worse, issue: see CreateKey.
                _logger.LogWarning(
                    "Template {Template} requires {Algorithm} keys, which this server cannot generate",
                    submitTemplate, lookup.KeyAlgorithm);
                return TlsEnrollmentResult.Failed(
                    $"Cannot enroll against template {submitTemplate}. {ex.Message} " +
                    $"Choose a template that uses one of those, or change this template's algorithm " +
                    $"on the Cryptography tab in the Certificate Templates console.");
            }
            catch (CryptographicException ex)
            {
                // A template's AD attributes drive the key size and curve;
                // an unusual or corrupt value (msPKI-Minimal-Key-Size in
                // particular) can be rejected by the platform's crypto
                // provider. Fail with the same structured result the rest
                // of this method returns, instead of an unhandled 500.
                _logger.LogWarning(ex,
                    "Could not create a {Algorithm} key for template {Template} (minimum size {MinimalKeySize})",
                    lookup.KeyAlgorithm ?? "RSA", submitTemplate, lookup.MinimalKeySize);
                return TlsEnrollmentResult.Failed(
                    $"Could not create a key matching template {submitTemplate}'s requirements " +
                    $"({lookup.KeyAlgorithm ?? "RSA"}, minimum {lookup.MinimalKeySize?.ToString() ?? "unknown"} bits): " +
                    $"{ex.Message}");
            }

            using var _ = key;
            var csrDer = BuildCsr(key, host);

            // The last point at which giving up costs nothing: no byte has reached
            // the CA and this enrollment has recorded nothing anywhere, so a caller
            // that has gone away gets the cheap answer here rather than a few lines
            // further on.
            cancellationToken.ThrowIfCancellationRequested();

            // Past this line the caller's token is never read again (issue #326,
            // the same shape issue #321 settled for the ACME finalize one subsystem
            // over). A submit is not idempotent, so a wizard tab closed mid
            // enrollment, or a service stopping mid renewal, can only cost the
            // certificate it just paid for: the CA issues it either way, and
            // abandoning the fetch leaves it live at the CA with nothing on this
            // server naming it, one more per cancelled attempt.
            //
            // Passing none to the submit itself is about the contract rather than
            // today's client. AdcsClient runs its Submit inside Task.Run(work,
            // token), an overload that only drops work before it starts, so a
            // cancellation observed there means the CSR never reached the CA.
            // IAdcsClient permits a client that aborts a request already on the
            // wire, and that client is the one this guards against.
            var submit = await client.SubmitCertificateRequestAsync(
                submitTemplate, csrDer, CancellationToken.None);

            // Sanitized here as well as inside AdcsClient (issue #362), for the
            // reason CertificateTextSanitizer's class doc gives: sanitizing at the
            // writer rather than only in each client is what makes the guard hold
            // for any IAdcsClient, and the two arms below write the CA's words into
            // a wizard screen, a settings screen and the log. The functions are
            // idempotent, so a value the COM client already cleaned is unchanged.
            // The log takes the flattened form, because a multi line CA message
            // otherwise reads back out of the log file as several records.
            //
            // What the CA said and why, composed once for the two arms below that
            // report a refusal (issue #356). Its own message was not enough on its
            // own: the lab CA answers a template Enroll denial with the bare "Denied
            // by Policy Module", so this surface, the one that meets a denial most
            // often, used to render a decision with no reason in it. Null when the CA
            // gave neither a message nor a code, which each arm's fallback covers.
            var caMessage = CertificateTextSanitizer.SanitizeDispositionMessage(
                submit.Message);
            var caMessageForLog = CertificateTextSanitizer.SanitizeDispositionMessageForLog(
                submit.Message);
            var refusal = CaStatusCode.DescribeRefusal(caMessage, submit.StatusCode);
            var refusalForLog = CaStatusCode.DescribeRefusal(
                caMessageForLog, submit.StatusCode);

            switch (submit.Status)
            {
                case SubmitStatus.Issued:
                    break;

                case SubmitStatus.Pending:
                    _logger.LogWarning(
                        "TLS certificate request {RequestId} pended for CA manager approval on template {Template}",
                        submit.RequestId, submitTemplate);
                    return TlsEnrollmentResult.Pending(
                        submit.RequestId,
                        $"The CA accepted the request but is holding it for CA manager approval " +
                        $"(request ID {submit.RequestId}). Manager approval defeats ACME automation: " +
                        $"every certificate request would wait for a person. Uncheck 'CA certificate " +
                        $"manager approval' on the Issuance Requirements tab of the {submitTemplate} " +
                        $"template, deny request {submit.RequestId} in the Certification Authority " +
                        $"console, and try again.",
                        submitTemplate);

                case SubmitStatus.Denied:
                    _logger.LogWarning(
                        "TLS certificate request denied on template {Template}: {Message}",
                        submitTemplate, refusalForLog ?? "no reason given.");
                    return TlsEnrollmentResult.Denied(
                        $"The CA denied the request: " +
                        $"{CaStatusCode.EndSentence(refusal ?? "no reason given")} " +
                        $"The service enrolls as the computer account {DescribeServiceAccount()}. " +
                        $"This usually means that account lacks Enroll permission: grant it Enroll " +
                        $"on the Security tab of the {submitTemplate} template and try again.",
                        submitTemplate);

                default:
                    return TlsEnrollmentResult.Failed(
                        $"The CA reported an error for the request: " +
                        $"{CaStatusCode.EndSentence(refusal ?? "no detail available")}",
                        submitTemplate);
            }

            // Everything from here runs on none as well, and a failure among these
            // steps means the CA holds a certificate for this host that this server
            // never installed. Nothing about an enrollment reaches the database, so
            // the log line in the catch is the only record that joins the two.
            try
            {
                var issued = await client.GetCertificateAsync(
                    submit.RequestId, CancellationToken.None);
                if (issued.Status != CertificateStatus.Issued || issued.CertificateDer is null)
                {
                    return TlsEnrollmentResult.Failed(
                        $"The CA reported the certificate as issued (request ID {submit.RequestId}) " +
                        $"but it could not be retrieved (status: {issued.Status}).",
                        submitTemplate);
                }

                using var leaf = X509CertificateLoader.LoadCertificate(issued.CertificateDer);

                // The CA does not reliably enforce its own template: the same
                // wrongly keyed request that one CA denies, another issues (issue
                // #213, observed on two labs in the same cycle). Check the leaf we
                // were actually given before installing it, so a certificate whose
                // key contradicts its template is refused here rather than serving
                // quietly for a year. CopyWithPrivateKey would throw on a mismatch
                // anyway; this turns that unhandled exception into a result the
                // wizard can render.
                if (!LeafMatchesKey(leaf, key))
                {
                    _logger.LogError(
                        "The CA issued request {RequestId} on template {Template} with a {Issued} key, but the " +
                        "request carried a {Requested} key. Not installing it.",
                        submit.RequestId, submitTemplate, DescribeLeafKey(leaf), DescribeRequestedKey(key));
                    return TlsEnrollmentResult.Failed(
                        $"The CA issued a certificate whose key does not match the request: it carries " +
                        $"{DescribeLeafKey(leaf)} where {DescribeRequestedKey(key)} was requested for template " +
                        $"{submitTemplate} (request ID {submit.RequestId}). The certificate was not installed. " +
                        $"Check the Cryptography tab of the {submitTemplate} template, and revoke request " +
                        $"{submit.RequestId} if it was issued in error.",
                        submitTemplate);
                }

                using var withKey = key switch
                {
                    RSA rsa => leaf.CopyWithPrivateKey(rsa),
                    ECDsa ecdsa => leaf.CopyWithPrivateKey(ecdsa),
                    _ => throw new InvalidOperationException($"Unsupported key type {key.GetType().Name}"),
                };
                var thumbprint = _certificateStore.Install(withKey);

                var issuedNames = GetSubjectNames(leaf);
                var externalHostCovered = CoversHost(issuedNames, host);
                var currentHostCovered = string.IsNullOrWhiteSpace(currentHost)
                    ? (bool?)null
                    : CoversHost(issuedNames, currentHost);

                _logger.LogInformation(
                    "TLS certificate issued (request ID {RequestId}, thumbprint {Thumbprint}) for template " +
                    "{Template}; names: {Names}; external host covered: {External}; browsing host covered: {Current}",
                    submit.RequestId, thumbprint, submitTemplate,
                    string.Join(", ", issuedNames), externalHostCovered, currentHostCovered);

                return new TlsEnrollmentResult(
                    Status: TlsEnrollmentStatus.Installed,
                    Thumbprint: thumbprint,
                    RequestId: submit.RequestId,
                    IssuedNames: issuedNames,
                    ExternalHostCovered: externalHostCovered,
                    CurrentHostCovered: currentHostCovered,
                    TemplateName: submitTemplate);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "The CA issued request {RequestId} on template {Template} for {Host}, and the " +
                    "enrollment could not finish, so a certificate may be live at the CA that this " +
                    "server never installed; revoke request {RequestId} by hand if it is not wanted",
                    submit.RequestId, submitTemplate, host, submit.RequestId);
                throw;
            }
        }
        finally
        {
            (client as IDisposable)?.Dispose();
        }
    }

    /// <summary>
    /// What the CA's published list says about the configured template: the
    /// CA's own programmatic name for it, and the key requirements the policy
    /// module will enforce.
    ///
    /// <see cref="ListRead"/> keeps two answers apart that a null
    /// <see cref="CanonicalName"/> alone would conflate, and they have opposite
    /// failure policies. True with no name means the CA answered and does not
    /// publish this template, which is a configuration error worth naming.
    /// False means the list could not be read at all, which says nothing about
    /// the template and must not block an enrollment.
    /// </summary>
    private readonly record struct TemplateLookup(
        bool ListRead,
        string? CanonicalName,
        string? KeyAlgorithm,
        int? MinimalKeySize);

    /// <summary>
    /// Resolve the configured template against the CA's published list, and
    /// read its key requirements from the same answer so the generated key
    /// matches what the CA policy module will enforce.
    ///
    /// Matches the programmatic name or the display name, case insensitive, the
    /// same dual form <see cref="Acme.Services.TemplateService.ResolveAsync"/>
    /// and <see cref="SetupService.ResolvePublishedTemplateNameAsync"/> accept.
    /// The caller's value selects a template; the CA's own name is what gets
    /// submitted, because ADCS matches <c>CertificateTemplate:</c> against the
    /// programmatic name alone (issue #194).
    ///
    /// Reading the list stays best effort: any CA or directory failure answers
    /// <see cref="TemplateLookup.ListRead"/> false, which leaves the caller on
    /// the configured name and the RSA default rather than blocking the
    /// enrollment on an AD read. The caller's own cancellation is the one thing
    /// that does come back out, because a caller that went away is not a CA that
    /// could not answer, and swallowing it would log the opposite.
    /// </summary>
    private async Task<TemplateLookup> ResolveTemplateAsync(
        IAdcsClient client,
        string templateName,
        CancellationToken cancellationToken)
    {
        try
        {
            var templates = await client.GetTemplatesAsync(cancellationToken);
            var template = templates.FirstOrDefault(t =>
                t.Name.Equals(templateName, StringComparison.OrdinalIgnoreCase)
                || t.DisplayName.Equals(templateName, StringComparison.OrdinalIgnoreCase));

            return new TemplateLookup(
                ListRead: true,
                CanonicalName: template?.Name,
                KeyAlgorithm: template?.Viability?.KeyAlgorithm,
                MinimalKeySize: template?.Viability?.MinimalKeySize);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Not a CA failure, so it must not fall through to the arm below,
            // which would log "enrolling with the configured name" for an
            // enrollment that is about to refuse at the guard before the submit.
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(
                ex,
                "Could not read the published template list to resolve {Template}; enrolling with " +
                "the configured name and defaulting to RSA {Bits}",
                templateName, MinimumRsaKeySizeBits);
            return new TemplateLookup(ListRead: false, null, null, null);
        }
    }

    /// <summary>
    /// The algorithms this enroller can generate a key for, named the way a
    /// template's <c>msPKI-Asymmetric-Algorithm</c> names them. Used only to
    /// tell an administrator what would work.
    /// </summary>
    private const string SupportedKeyAlgorithms = "RSA, ECDSA_P256, ECDSA_P384, ECDSA_P521";

    /// <summary>
    /// Whether a template's algorithm names an elliptic curve Diffie Hellman
    /// key, which <see cref="CreateKey"/> answers with an ECDSA key on the same
    /// curve.
    /// </summary>
    /// <remarks>
    /// Callers use this to warn. The substitution always works, but a template
    /// naming ECDH is still almost certainly misconfigured for a TLS purpose,
    /// and the administrator is the only one who can put that right.
    /// </remarks>
    internal static bool IsEcdhAlgorithm(string? keyAlgorithm) =>
        keyAlgorithm?.Trim().ToUpperInvariant().StartsWith("ECDH", StringComparison.Ordinal) == true;

    /// <summary>
    /// Create the key pair the template asks for. Elliptic curve templates get
    /// a key on the matching NIST curve (from the algorithm name suffix, or the
    /// minimum key size when the name carries no curve). RSA, and an algorithm
    /// that could not be determined at all, get RSA at the template minimum
    /// with a 2048 bit floor.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A template that names an algorithm we cannot generate is refused rather
    /// than quietly given an RSA key. Silently substituting one algorithm for
    /// another is what issue #213 was about: a CA that enforces its template
    /// denies the request with nothing naming the cause, and a CA that does not
    /// issues a certificate whose key type contradicts its own template. An
    /// unknown algorithm is a different case and still gets RSA, because there
    /// the template said nothing to contradict.
    /// </para>
    /// <para>
    /// <c>ECDH_P256</c> and its siblings are answered with an <see cref="ECDsa"/>
    /// key on the named curve, and that is deliberately not the substitution
    /// above (issue #277). Three facts make it a different case. A PKCS#10 is
    /// self signed, so it cannot carry an encryption only key at all, and no
    /// enrollment client anywhere can produce one. Per RFC 5480 both keys
    /// encode identically as <c>id-ecPublicKey</c> plus a named curve, so the
    /// bytes the CA reads are the same either way. And the lab CA issued
    /// against exactly such a template on 2026-08-15, next to a control that
    /// isolated the template attribute as the only variable. So the curve is
    /// the whole of what the template actually constrains, and honouring it is
    /// not contradicting the template the way an RSA key would.
    /// </para>
    /// <para>
    /// ADCS records ECDH when the template's Request Handling tab Purpose is
    /// "Signature and encryption" rather than "Signature": the same run showed
    /// the private key usage inside <c>msPKI-RA-Application-Policies</c> moving
    /// from <c>16777215</c> (all usages) to <c>2</c> (signing) when Purpose was
    /// the only setting changed, and the algorithm name moving with it. That is
    /// why <see cref="IsEcdhAlgorithm"/> exists: the enrollment succeeds, and
    /// the caller still says so.
    /// </para>
    /// </remarks>
    /// <exception cref="NotSupportedException">
    /// The template names an algorithm outside <see cref="SupportedKeyAlgorithms"/>.
    /// </exception>
    internal static AsymmetricAlgorithm CreateKey(string? keyAlgorithm, int? minimalKeySize)
    {
        var algorithm = keyAlgorithm?.Trim().ToUpperInvariant();
        if (algorithm is null || algorithm.Length == 0 || algorithm == "RSA")
            return RSA.Create(Math.Max(MinimumRsaKeySizeBits, minimalKeySize ?? MinimumRsaKeySizeBits));

        // The two prefixes are disjoint, so neither test can catch the other's
        // names, and bare "DH" matches neither and stays refused.
        if (!algorithm.StartsWith("ECDSA", StringComparison.Ordinal)
            && !algorithm.StartsWith("ECDH", StringComparison.Ordinal))
        {
            throw new NotSupportedException(
                $"The template requires {keyAlgorithm!.Trim()} keys, which this server cannot generate. " +
                $"Supported: {SupportedKeyAlgorithms}.");
        }

        var curve = algorithm.EndsWith("P384", StringComparison.Ordinal) ? ECCurve.NamedCurves.nistP384
            : algorithm.EndsWith("P521", StringComparison.Ordinal) ? ECCurve.NamedCurves.nistP521
            : algorithm.EndsWith("P256", StringComparison.Ordinal) ? ECCurve.NamedCurves.nistP256
            : minimalKeySize switch
            {
                >= 521 => ECCurve.NamedCurves.nistP521,
                >= 384 => ECCurve.NamedCurves.nistP384,
                _ => ECCurve.NamedCurves.nistP256,
            };
        return ECDsa.Create(curve);
    }

    /// <summary>
    /// Whether an issued leaf actually carries a key of the type we generated.
    /// </summary>
    /// <remarks>
    /// The CA is not a reliable backstop for its own template. Issue #213 was
    /// observed on two labs at once: one CA denied an RSA request against an
    /// ECDSA only template, and the other issued it, leaving a working
    /// certificate whose key type contradicted the template it was issued
    /// under and nothing anywhere saying so. This is the check that makes the
    /// second case visible.
    /// </remarks>
    private static bool LeafMatchesKey(X509Certificate2 leaf, AsymmetricAlgorithm key)
    {
        // The reads below throw on a key blob the platform cannot import, an
        // unsupported curve or explicit curve parameters among them, and this
        // method exists precisely to distrust what the CA handed back. Treat
        // that as a mismatch: a key we cannot even read is one we must not
        // install, and CopyWithPrivateKey would fail on it a few lines later
        // regardless. CertificateDerParser.ReadKeySizeBits guards the same
        // calls the same way for the same reason.
        try
        {
            switch (key)
            {
                case RSA rsa:
                    using (var leafRsa = leaf.GetRSAPublicKey())
                        return leafRsa is not null && leafRsa.KeySize == rsa.KeySize;
                case ECDsa ecdsa:
                    using (var leafEcdsa = leaf.GetECDsaPublicKey())
                        return leafEcdsa is not null && leafEcdsa.KeySize == ecdsa.KeySize;
                default:
                    return false;
            }
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <summary>
    /// Name a key the way <see cref="CertificateDerParser"/> names one, for a
    /// message an administrator can act on ("RSA 2048", "ECDSA 256").
    /// </summary>
    private static string DescribeLeafKey(X509Certificate2 leaf)
    {
        var algorithm = CertificateDerParser.ReadKeyAlgorithm(leaf) ?? "an unrecognised algorithm";
        var bits = CertificateDerParser.ReadKeySizeBits(leaf);
        return bits is { } size ? $"{algorithm} {size}" : algorithm;
    }

    private static string DescribeRequestedKey(AsymmetricAlgorithm key) => key switch
    {
        RSA rsa => $"RSA {rsa.KeySize}",
        ECDsa ecdsa => $"ECDSA {ecdsa.KeySize}",
        _ => key.GetType().Name,
    };

    /// <summary>
    /// Build the PKCS#10 request: CN and a single SAN entry for the external
    /// host. Deliberately no extra names — machine names or localhost in a CA
    /// issued server certificate are poor hygiene, and the wizard handles a
    /// browsing session on another host with the continue link instead.
    /// EC keys do not encipher, so their key usage is signature only; some
    /// policy modules reject an EC request that claims KeyEncipherment.
    /// </summary>
    internal static byte[] BuildCsr(AsymmetricAlgorithm key, string host)
    {
        var dn = new X500DistinguishedName($"CN={host}");
        var request = key switch
        {
            RSA rsa => new CertificateRequest(dn, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            ECDsa ecdsa => new CertificateRequest(dn, ecdsa, HashAlgorithmName.SHA256),
            _ => throw new ArgumentException($"Unsupported key type {key.GetType().Name}", nameof(key)),
        };

        var keyUsage = key is RSA
            ? X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment
            : X509KeyUsageFlags.DigitalSignature;
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(keyUsage, critical: false));
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid(SetupService.ServerAuthEku) },
                critical: false));

        var san = new SubjectAlternativeNameBuilder();
        if (IPAddress.TryParse(host, out var ip))
            san.AddIpAddress(ip);
        else
            san.AddDnsName(host);
        request.CertificateExtensions.Add(san.Build());

        return request.CreateSigningRequest();
    }

    /// <summary>
    /// The DNS and IP names the certificate is valid for: the SAN entries,
    /// or the CN when the certificate has no SAN extension (verifiers ignore
    /// the CN when a SAN is present, so the two are never mixed).
    /// </summary>
    public static IReadOnlyList<string> GetSubjectNames(X509Certificate2 certificate)
    {
        var names = new List<string>();
        foreach (var extension in certificate.Extensions)
        {
            if (extension is X509SubjectAlternativeNameExtension san)
            {
                names.AddRange(san.EnumerateDnsNames());
                names.AddRange(san.EnumerateIPAddresses().Select(a => a.ToString()));
            }
        }

        if (names.Count == 0)
        {
            var cn = certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
            if (!string.IsNullOrWhiteSpace(cn))
                names.Add(cn);
        }

        return names;
    }

    /// <summary>
    /// Whether any of the certificate names covers the host, the way a TLS
    /// verifier would: case insensitive exact match, a single label wildcard
    /// (*.example.com covers a.example.com but not b.a.example.com), or IP
    /// address equality.
    /// </summary>
    public static bool CoversHost(IEnumerable<string> names, string host)
    {
        var hostIsIp = IPAddress.TryParse(host, out var hostIp);

        foreach (var name in names)
        {
            if (string.Equals(name, host, StringComparison.OrdinalIgnoreCase))
                return true;

            if (hostIsIp && IPAddress.TryParse(name, out var nameIp) && nameIp.Equals(hostIp))
                return true;

            if (!hostIsIp && name.StartsWith("*.", StringComparison.Ordinal))
            {
                var dot = host.IndexOf('.');
                if (dot > 0 &&
                    string.Equals(host[(dot + 1)..], name[2..], StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }

        return false;
    }

    /// <summary>
    /// Name the identity the CA sees, for the denial message: the machine
    /// account, qualified with the DNS domain when the host is domain joined.
    /// </summary>
    internal static string DescribeServiceAccount()
    {
        var machineAccount = Environment.MachineName + "$";
        var domain = IPGlobalProperties.GetIPGlobalProperties().DomainName;
        return string.IsNullOrEmpty(domain)
            ? machineAccount
            : $"{machineAccount} in domain {domain}";
    }
}

/// <summary>How a TLS certificate enrollment attempt ended.</summary>
public enum TlsEnrollmentStatus
{
    /// <summary>Issued and installed into the HTTPS certificate store.</summary>
    Installed,

    /// <summary>The CA pended the request for manager approval.</summary>
    Pending,

    /// <summary>The CA denied the request.</summary>
    Denied,

    /// <summary>Any other failure, including retrieval problems.</summary>
    Failed,
}

/// <summary>
/// Outcome of <see cref="TlsCertificateEnroller.EnrollAsync"/>. On
/// <see cref="TlsEnrollmentStatus.Installed"/> the coverage flags say whether
/// the issued names include the external URL host (they will not when the
/// template builds the subject from AD) and the host the admin is browsing
/// on (null when unknown).
///
/// <see cref="TemplateName"/> is the name that reached the CA, which is the
/// CA's own programmatic name whenever the published list could be read. It is
/// null on the refusals that never got as far as submitting. A caller that
/// records the template should record this rather than what it passed in, so
/// an install configured with a display name converges on the name ADCS
/// actually matches (issue #194).
/// </summary>
public sealed record TlsEnrollmentResult(
    TlsEnrollmentStatus Status,
    string? Thumbprint = null,
    int? RequestId = null,
    IReadOnlyList<string>? IssuedNames = null,
    bool ExternalHostCovered = false,
    bool? CurrentHostCovered = null,
    string? Message = null,
    string? TemplateName = null)
{
    public static TlsEnrollmentResult Pending(int requestId, string message, string? templateName = null) =>
        new(TlsEnrollmentStatus.Pending, RequestId: requestId, Message: message, TemplateName: templateName);

    public static TlsEnrollmentResult Denied(string message, string? templateName = null) =>
        new(TlsEnrollmentStatus.Denied, Message: message, TemplateName: templateName);

    public static TlsEnrollmentResult Failed(string message, string? templateName = null) =>
        new(TlsEnrollmentStatus.Failed, Message: message, TemplateName: templateName);
}

namespace Certus.Core.Adcs;

/// <summary>
/// The HRESULT a certification authority records against a request, and what it
/// means (issue #356).
///
/// A denied request carries two things back from ADCS and we used to read only
/// one of them. <c>ICertRequest::GetDispositionMessage</c> is the CA's own
/// sentence, and on a stock Windows CA that sentence is the bare string
/// "Denied by Policy Module": a decision, with no reason attached (request 109,
/// 2026-08-24). <c>ICertRequest::GetLastStatus</c> is the reason, and it is the
/// same value <c>certutil -view -restrict "RequestId=N" -out
/// "Request.StatusCode"</c> reports and the same value
/// <see cref="CertificateInfo.StatusCode"/> already carries out of the CA view.
///
/// This lives in Certus.Core rather than in Certus.Adcs because four consumers
/// need it and only one of them is the COM client: <c>AdcsClient</c> reads the
/// code, <c>OrderService</c> puts it on the ACME wire,
/// <c>TlsCertificateEnroller</c> puts it in the wizard, and
/// <see cref="MockAdcsClient"/> produces it. Certus.Core.Tests cannot reference
/// Certus.Adcs at all, which is the same reasoning that moved
/// <see cref="CertificateTextSanitizer"/> here in issue #224.
///
/// The descriptions are Microsoft's own wording, verbatim, from the winerror.h
/// listing. That is deliberate: it is the text <c>certutil -error</c> prints for
/// the same code, so an operator reading our log and an operator running the
/// tool see one explanation rather than two that have to be reconciled. Writing
/// our own would also mean describing conditions we have never observed.
///
/// The set is an allow list of codes we have verified, not an attempt at the
/// whole of winerror.h. A code that is not here still reaches every surface as
/// hex, which is more than the bare message gave, and is the reason a partial
/// map is worth having at all.
/// </summary>
public static class CaStatusCode
{
    /// <summary>The request subject name is invalid or too long.</summary>
    public const int BadRequestSubject = unchecked((int)0x80094001);

    /// <summary>The CA's own permissions refuse this caller.</summary>
    public const int EnrollDenied = unchecked((int)0x80094011);

    /// <summary>
    /// The template's permissions refuse this caller. The commonest denial this
    /// product meets, and the one <c>DescribeDenialRemedy</c> and the wizard
    /// both give an operator remedy for.
    /// </summary>
    public const int TemplateDenied = unchecked((int)0x80094012);

    /// <summary>
    /// A certificate manager denied a request that was held for approval. This
    /// is the outcome the pending issuance sweep exists to discover, so it is in
    /// the map even though the sweep cannot read the code today; see the remarks
    /// on <see cref="Describe"/>.
    /// </summary>
    public const int AdminDeniedRequest = unchecked((int)0x80094014);

    /// <summary>
    /// The template is not published by this CA. Issue #194's code: a display
    /// name reached the CA where a programmatic name was needed, ACME issued
    /// fine against the same template, and diagnosing it cost a lab round trip
    /// because nothing named this.
    /// </summary>
    public const int UnsupportedCertType = unchecked((int)0x80094800);

    /// <summary>The request named no template at all.</summary>
    public const int NoCertType = unchecked((int)0x80094801);

    /// <summary>The request named more than one template, or named it twice.</summary>
    public const int TemplateConflict = unchecked((int)0x80094802);

    /// <summary>The template demands a subject alternative name the CSR has none of.</summary>
    public const int SubjectAltNameRequired = unchecked((int)0x80094803);

    /// <summary>The template is a newer schema than this CA understands.</summary>
    public const int BadTemplateVersion = unchecked((int)0x80094807);

    /// <summary>The template demands signature policy information the request lacks.</summary>
    public const int SignaturePolicyRequired = unchecked((int)0x80094809);

    /// <summary>
    /// The template demands enrollment agent signatures, which an ACME CSR never
    /// carries. <see cref="TemplateAcmeViability.RequiresRaSignatures"/> warns
    /// about this in advance; this is the same condition confirming itself after
    /// the fact.
    /// </summary>
    public const int SignatureCount = unchecked((int)0x8009480A);

    /// <summary>The template demands a DNS name that is not available to the CA.</summary>
    public const int SubjectDnsRequired = unchecked((int)0x8009480F);

    /// <summary>
    /// The key is smaller than the template's minimum.
    /// <see cref="TemplateAcmeViability.MinimalKeySize"/> is the advance warning
    /// for this one.
    /// </summary>
    public const int KeyLength = unchecked((int)0x80094811);

    /// <summary>The template demands an email name that is not available to the CA.</summary>
    public const int SubjectEmailRequired = unchecked((int)0x80094812);

    /// <summary>The template demands renewal on the same public key.</summary>
    public const int RenewalBadPublicKey = unchecked((int)0x80094816);

    /// <summary>
    /// The verified codes and Microsoft's own description of each.
    ///
    /// Frozen deliberately at what has been read off the winerror.h listing. An
    /// earlier draft of issue #356 recorded <c>CERTSRV_E_SUBJECT_EMAIL_REQUIRED</c>
    /// as 0x80094003, which is really <c>CERTSRV_E_BAD_REQUESTSTATUS</c> ("the
    /// request's current status does not allow this operation") and not a submit
    /// time denial reason at all. A wrong entry here is worse than a missing one,
    /// because a missing code still surfaces as hex and a wrong one confidently
    /// misdescribes what happened.
    /// </summary>
    private static readonly IReadOnlyDictionary<int, string> Descriptions =
        new Dictionary<int, string>
        {
            [BadRequestSubject] = "The request subject name is invalid or too long.",
            [EnrollDenied] =
                "The permissions on this certification authority do not allow the current " +
                "user to enroll for certificates.",
            [TemplateDenied] =
                "The permissions on the certificate template do not allow the current user " +
                "to enroll for this type of certificate.",
            [AdminDeniedRequest] =
                "The request was denied by a certificate manager or CA administrator.",
            [UnsupportedCertType] =
                "The requested certificate template is not supported by this CA.",
            [NoCertType] = "The request contains no certificate template information.",
            [TemplateConflict] = "The request contains conflicting template information.",
            [SubjectAltNameRequired] =
                "The request is missing a required Subject Alternate name extension.",
            [BadTemplateVersion] =
                "The request template version is newer than the supported template version.",
            [SignaturePolicyRequired] =
                "The request is missing required signature policy information.",
            [SignatureCount] = "The request is missing one or more required signatures.",
            [SubjectDnsRequired] =
                "The DNS name is unavailable and cannot be added to the Subject Alternate name.",
            [KeyLength] =
                "The public key does not meet the minimum size required by the specified " +
                "certificate template.",
            [SubjectEmailRequired] =
                "The EMail name is unavailable and cannot be added to the Subject or Subject " +
                "Alternate name.",
            [RenewalBadPublicKey] =
                "The certificate template requires renewal with the same public key, but the " +
                "request uses a different public key.",
        };

    /// <summary>
    /// Every code this class names, for the tests that assert the map rather than
    /// a number.
    ///
    /// Materialised once rather than cast from <c>Descriptions.Keys</c>, which is
    /// statically an IEnumerable and only happens to be a collection because the
    /// backing store is a Dictionary. That cast would keep compiling and start
    /// throwing at runtime the day the map became a FrozenDictionary.
    /// </summary>
    public static IReadOnlyCollection<int> KnownCodes { get; } = Descriptions.Keys.ToArray();

    /// <summary>
    /// The code in the 0x8009xxxx form an operator can search for and hand to
    /// <c>certutil -error</c>.
    ///
    /// The CA records the value signed, so it arrives here negative. The X8
    /// format writes the two's complement bits, which is exactly the unsigned
    /// spelling wanted, and matches what the dashboard's <c>formatHResult</c>
    /// produces for the same value out of the CA view.
    /// </summary>
    public static string Format(int code) => $"0x{code:X8}";

    /// <summary>
    /// Microsoft's description of a code, or null for one this class does not
    /// name.
    ///
    /// Null is a normal answer and not a failure. ADCS policy modules are
    /// pluggable and a third party one may record codes of its own, so callers
    /// fall back to the hex spelling rather than to silence.
    /// </summary>
    public static string? Describe(int code) =>
        Descriptions.TryGetValue(code, out var description) ? description : null;

    /// <summary>
    /// The code and its meaning as one finished sentence, or null when there is
    /// nothing to say.
    ///
    /// Zero is nothing to say. <c>GetLastStatus</c> returns S_OK after a call
    /// that succeeded, and the CA view records zero on an issued row, so a zero
    /// here means the request was not refused rather than that it was refused
    /// for reason zero. <see cref="AdcsClient"/> has treated the view's column
    /// this way since issue #150 and this keeps the two readings identical.
    ///
    /// A code with no description says so in words rather than standing alone as
    /// a bare number. It leads with the hex either way, so the value an operator
    /// copies into <c>certutil -error</c> sits at the front of the sentence and
    /// never picks up the trailing full stop.
    /// </summary>
    public static string? Explain(int? code)
    {
        if (code is not { } value || value == 0)
            return null;

        var description = Describe(value);
        return description is null
            ? $"{Format(value)}: no description is recorded for this code."
            : $"{Format(value)}: {description}";
    }

    /// <summary>
    /// What a CA refusal says, composed once for every surface that reports one.
    ///
    /// The CA's own message leads and the explanation follows in parentheses,
    /// because the decision is the CA's to report and not ours to paraphrase.
    /// The explanation is added beside it rather than in place of it for the same
    /// reason: a policy module that does explain itself must not have its own
    /// words replaced by ours.
    ///
    /// One composer rather than three literals, for the reason
    /// <c>OrderService.DescribeDenialRemedy</c> already states beside it. A
    /// refusal is reported by the submit's own log line, by the ACME finalize,
    /// and by the setup wizard, and those three have to say the same thing about
    /// one refusal or an operator comparing two of them learns nothing.
    ///
    /// Two sentences joined rather than an explanation parenthesised inside the
    /// CA's own, because the descriptions end in a full stop and nesting one
    /// inside brackets reads as ".)." wherever a caller continues the paragraph,
    /// which the setup wizard does.
    ///
    /// **A message standing alone comes back byte identical.** Punctuation is
    /// added only at a boundary this method itself creates, which is the line
    /// issue #362 drew: the CA's decision reaches the client in its own words and
    /// not its own bytes, and adding a full stop to a message we are not joining
    /// anything onto would be changing the words for no reader's benefit. A caller
    /// that goes on to embed the result in a longer paragraph terminates it with
    /// <see cref="EndSentence"/> at the point of use instead, which is a no op on
    /// the joined form.
    ///
    /// Returns null when the CA gave neither a message nor a code, so each caller
    /// keeps its own fallback wording for a CA that said nothing at all.
    /// </summary>
    public static string? DescribeRefusal(string? caMessage, int? statusCode)
    {
        var message = string.IsNullOrWhiteSpace(caMessage) ? null : caMessage.Trim();
        var explanation = Explain(statusCode);

        return (message, explanation) switch
        {
            (null, null) => null,
            (null, not null) => explanation,
            (not null, null) => message,
            _ => $"{EndSentence(message)} {explanation}",
        };
    }

    /// <summary>
    /// The value with a full stop, unless it already ends a sentence.
    ///
    /// Only the CA's own message needs this. It is written by a policy module we
    /// do not control, and the one a stock CA sends ("Denied by Policy Module")
    /// carries no punctuation at all, so joining a second sentence onto it
    /// unchanged would run the two together.
    ///
    /// Public because the boundary is not always one this class creates. The setup
    /// wizard continues the paragraph after the refusal with its own remediation
    /// sentence, so it terminates the value at the point of use. Idempotent, so
    /// calling it on an already joined refusal changes nothing.
    ///
    /// The ellipsis counts as an ending. A message over
    /// <see cref="CertificateTextSanitizer.MaxDispositionMessageLength"/> arrives
    /// here already cut and marked with one, and following that with a full stop
    /// reads as a typo rather than as punctuation.
    /// </summary>
    public static string EndSentence(string value) =>
        value.EndsWith('.') || value.EndsWith('!') || value.EndsWith('?')
        || value.EndsWith('…')
            ? value
            : value + ".";
}

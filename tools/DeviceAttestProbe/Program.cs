using System.Formats.Asn1;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certus.Core.Adcs;

// Diagnostic for the ACME device-attest-01 feature.
//
// draft-ietf-acme-device-attest-08 expects the issued certificate to carry the
// device identity as an RFC 4043 PermanentIdentifier otherName in the
// SubjectAltName when the client's CSR requests it. Ducks in a Row hands ADCS
// the raw client CSR with a single CertificateTemplate:<name> attribute and
// never injects subject content itself, so the identity reaches the issued
// certificate only if the CA preserves the otherName from the CSR on an
// enrollee-supplies-subject template.
//
// Whether ADCS preserves, strips, or re-encodes that otherName is exactly the
// kind of runtime fact this project does not guess at (see the AdcsQiProbe
// history: probe first, then write source). This probe submits three CSRs:
//
//   Run A: SAN = otherName PermanentIdentifier { "PROBE-SN-0001" }
//   Run B: SAN = otherName PermanentIdentifier { "PROBE-SN-0001", assigner OID }
//   Run C: SAN = otherName as in A plus a dNSName, to detect selective
//          stripping (a policy module may keep DNS names and drop otherName).
//
// For each run it prints the SAN as constructed, submits, and if the CA issues,
// re-parses the issued certificate's SAN and prints a verdict line:
//
//   OTHERNAME PRESERVED: yes | no | reencoded
//
// Configuration comes from the environment, matching AdcsQiProbe:
//   CERTUS_PROBE_CA       "<host>\<CA name>"   (required)
//   CERTUS_PROBE_TEMPLATE "<template name>"    (required; must be a template
//                          with enrollee-supplies-subject that the probe user
//                          may enroll on)
//
// A Denied disposition usually means template permissions, not an otherName
// answer; the probe says so rather than pretending it learned something.

Console.WriteLine("Certus DeviceAttestProbe — PermanentIdentifier otherName passthrough diagnostic");
Console.WriteLine($"Process: PID={Environment.ProcessId}, User={Environment.UserDomainName}\\{Environment.UserName}, Bitness={(IntPtr.Size == 8 ? "x64" : "x86")}");
Console.WriteLine();

string? caConfig = Environment.GetEnvironmentVariable("CERTUS_PROBE_CA");
string? template = Environment.GetEnvironmentVariable("CERTUS_PROBE_TEMPLATE");
if (string.IsNullOrWhiteSpace(caConfig) || string.IsNullOrWhiteSpace(template))
{
    Console.WriteLine("Skipped: set CERTUS_PROBE_CA=\"<host>\\<CA name>\" and CERTUS_PROBE_TEMPLATE=\"<template>\" to enable.");
    return;
}

// The template name comes from the environment, so it is operator supplied
// rather than resolved against the CA's published list. Check it once here,
// before three runs fail identically, with the same guard the product submits
// through. A probe that pointed a live CA at a smuggled cdc/rmd attribute would
// be an attack tool rather than a diagnostic (issue #175, CVE-2026-54121).
if (!AdcsRequestAttributes.TryValidateTemplateName(template, out var templateError))
{
    Console.WriteLine($"Skipped: {templateError}");
    return;
}

Console.WriteLine($"CA config: {caConfig}");
Console.WriteLine($"Template:  {template}");
Console.WriteLine();

var runs = new (string Label, string Value, string? Assigner, string? DnsName)[]
{
    ("Run A: otherName only",            "PROBE-SN-0001", null,                    null),
    ("Run B: otherName with assigner",   "PROBE-SN-0001", "1.3.6.1.4.1.99999.1",   null),
    ("Run C: otherName plus dNSName",    "PROBE-SN-0001", null,                    "device-attest-probe.home.local"),
};

foreach (var run in runs)
{
    Console.WriteLine($"=== {run.Label} ===");
    try
    {
        ProbeRun.Execute(caConfig, template, run.Value, run.Assigner, run.DnsName);
    }
    catch (COMException ex)
    {
        Console.WriteLine($"  COM failure: 0x{ex.HResult:X8} {ex.Message}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"  Failure: {ex.GetType().Name}: {ex.Message}");
    }
    Console.WriteLine();
}

internal static class ProbeRun
{
    // ICertRequest::Submit flags and dispositions, duplicated inline per the
    // tools/ convention (AdcsQiProbe does the same) so the probe stays
    // standalone and never links Certus.Adcs.
    private const int EncodingBase64 = 0x1;
    private const int FormatPkcs10 = 0x100;
    private const int OutputBase64 = 0x1;

    private const int DispositionError = 0x1;
    private const int DispositionDenied = 0x2;
    private const int DispositionIssued = 0x3;
    private const int DispositionIssuedOutOfBand = 0x4;
    private const int DispositionUnderSubmission = 0x5;

    private const string IdOnPermanentIdentifier = "1.3.6.1.5.5.7.8.3";
    private const string SubjectAltNameOid = "2.5.29.17";

    public static void Execute(string caConfig, string template, string value, string? assigner, string? dnsName)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            $"CN={value}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        byte[] san = BuildSubjectAltName(value, assigner, dnsName);
        request.CertificateExtensions.Add(new X509Extension(SubjectAltNameOid, san, critical: false));

        Console.WriteLine("  CSR SAN as constructed:");
        DumpGeneralNames(san, indent: "    ");

        byte[] csrDer = request.CreateSigningRequest();
        string csrBase64 = Convert.ToBase64String(csrDer);

        var certRequest = new CertRequestClass();
        dynamic d = certRequest;
        try
        {
            // Built through the product's own guard rather than interpolated
            // here, so this probe cannot be the one place in the repo that
            // hands ADCS an unchecked request attribute string.
            int disposition = (int)d.Submit(
                EncodingBase64 | FormatPkcs10, csrBase64,
                AdcsRequestAttributes.ForTemplate(template), caConfig);
            int requestId = (int)d.GetRequestId();
            string dispositionMessage;
            try { dispositionMessage = (string)d.GetDispositionMessage(); }
            catch { dispositionMessage = "(no disposition message)"; }

            Console.WriteLine($"  Submit -> disposition {disposition} ({DispositionName(disposition)}), request id {requestId}");
            Console.WriteLine($"  Disposition message: {dispositionMessage.Trim()}");

            switch (disposition)
            {
                case DispositionIssued:
                case DispositionIssuedOutOfBand:
                    string certBase64 = (string)d.GetCertificate(OutputBase64);
                    var cert = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(certBase64));
                    ReportIssuedCertificate(cert, value, assigner, dnsName);
                    break;

                case DispositionUnderSubmission:
                    Console.WriteLine("  Verdict: PENDING — the template requires manager approval; the probe cannot");
                    Console.WriteLine("  answer the passthrough question on this template. Pick one that auto-issues.");
                    break;

                case DispositionDenied:
                    Console.WriteLine("  Verdict: DENIED — usually template enroll permissions or subject policy, not an");
                    Console.WriteLine("  otherName answer. Check the CA's failed request log for the request id above.");
                    break;

                default:
                    Console.WriteLine("  Verdict: ERROR — submission did not reach a disposition the probe understands.");
                    break;
            }
        }
        finally
        {
            Marshal.FinalReleaseComObject(certRequest);
        }
    }

    private static void ReportIssuedCertificate(X509Certificate2 cert, string value, string? assigner, string? dnsName)
    {
        Console.WriteLine($"  Issued: serial {cert.SerialNumber}, subject {cert.Subject}");

        var sanExtension = cert.Extensions[SubjectAltNameOid];
        if (sanExtension == null)
        {
            Console.WriteLine("  Issued certificate has NO SubjectAltName extension at all.");
            Console.WriteLine("  OTHERNAME PRESERVED: no");
            return;
        }

        Console.WriteLine("  Issued certificate SAN:");
        var found = DumpGeneralNames(sanExtension.RawData, indent: "    ");

        bool valueMatch = found.PermanentIdentifiers.Any(p =>
            string.Equals(p.Value, value, StringComparison.Ordinal) &&
            string.Equals(p.Assigner, assigner, StringComparison.Ordinal));

        // The seen counter, not the parsed value list, decides stripped versus
        // reencoded: a CA that rewrites the UTF8String as another string type
        // leaves the otherName present but unreadable to the strict parser, and
        // that must not be reported as stripped.
        if (valueMatch)
            Console.WriteLine("  OTHERNAME PRESERVED: yes");
        else if (found.PermanentIdentifierOtherNames > 0)
            Console.WriteLine("  OTHERNAME PRESERVED: reencoded (present but value, type, or assigner differs — see dump above)");
        else
            Console.WriteLine("  OTHERNAME PRESERVED: no (stripped by the CA)");

        if (dnsName != null)
        {
            Console.WriteLine(found.DnsNames.Contains(dnsName, StringComparer.OrdinalIgnoreCase)
                ? $"  dNSName '{dnsName}' preserved: yes"
                : $"  dNSName '{dnsName}' preserved: no");
        }

        bool cnPreserved = cert.Subject.Contains($"CN={value}", StringComparison.Ordinal);
        Console.WriteLine($"  Subject CN preserved: {(cnPreserved ? "yes" : "no")}");
    }

    private static string DispositionName(int disposition) => disposition switch
    {
        0 => "Incomplete",
        DispositionError => "Error",
        DispositionDenied => "Denied",
        DispositionIssued => "Issued",
        DispositionIssuedOutOfBand => "IssuedOutOfBand",
        DispositionUnderSubmission => "UnderSubmission",
        6 => "Revoked",
        _ => "Unknown",
    };

    // GeneralNames ::= SEQUENCE OF GeneralName
    // GeneralName otherName is [0] IMPLICIT OtherName; OtherName ::= SEQUENCE
    // { type-id OBJECT IDENTIFIER, value [0] EXPLICIT ANY }. For
    // id-on-permanentIdentifier the value is PermanentIdentifier ::= SEQUENCE
    // { identifierValue UTF8String OPTIONAL, assigner OBJECT IDENTIFIER OPTIONAL }
    // (RFC 4043 section 2).
    private static byte[] BuildSubjectAltName(string value, string? assigner, string? dnsName)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            var otherNameTag = new Asn1Tag(TagClass.ContextSpecific, 0);
            using (writer.PushSequence(otherNameTag))
            {
                writer.WriteObjectIdentifier(IdOnPermanentIdentifier);
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    using (writer.PushSequence())
                    {
                        writer.WriteCharacterString(UniversalTagNumber.UTF8String, value);
                        if (assigner != null)
                            writer.WriteObjectIdentifier(assigner);
                    }
                }
            }

            if (dnsName != null)
            {
                writer.WriteCharacterString(
                    UniversalTagNumber.IA5String, dnsName, new Asn1Tag(TagClass.ContextSpecific, 2));
            }
        }
        return writer.Encode();
    }

    internal sealed record ParsedSan(
        List<(string Value, string? Assigner)> PermanentIdentifiers,
        List<string> DnsNames,
        int PermanentIdentifierOtherNames);

    private static ParsedSan DumpGeneralNames(byte[] rawSan, string indent)
    {
        var permanentIdentifiers = new List<(string Value, string? Assigner)>();
        var dnsNames = new List<string>();
        int permanentIdentifierOtherNames = 0;

        var reader = new AsnReader(rawSan, AsnEncodingRules.DER);
        var names = reader.ReadSequence();
        // A parse failure inside one GeneralName must not abort the run after the
        // CA already issued; the verdict is the whole point of the probe. On the
        // first unreadable element, report it and stop the dump (the reader
        // cannot safely continue mid element), leaving the counts gathered so far.
        try
        {
            while (names.HasData)
            {
                var tag = names.PeekTag();
                if (tag.TagClass == TagClass.ContextSpecific && tag.TagValue == 0)
                {
                    var otherName = names.ReadSequence(tag);
                    string typeId = otherName.ReadObjectIdentifier();
                    var explicitValue = otherName.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));

                    if (typeId == IdOnPermanentIdentifier)
                    {
                        permanentIdentifierOtherNames++;
                        var permanentIdentifier = explicitValue.ReadSequence();
                        string? value = null;
                        string? assigner = null;
                        if (permanentIdentifier.HasData &&
                            permanentIdentifier.PeekTag() == new Asn1Tag(UniversalTagNumber.UTF8String))
                            value = permanentIdentifier.ReadCharacterString(UniversalTagNumber.UTF8String);
                        if (permanentIdentifier.HasData &&
                            permanentIdentifier.PeekTag() == new Asn1Tag(UniversalTagNumber.ObjectIdentifier))
                            assigner = permanentIdentifier.ReadObjectIdentifier();

                        Console.WriteLine($"{indent}otherName PermanentIdentifier: value='{value}' assigner={(assigner ?? "(none)")}");
                        if (value != null)
                            permanentIdentifiers.Add((value, assigner));
                    }
                    else
                    {
                        Console.WriteLine($"{indent}otherName type-id {typeId} (not PermanentIdentifier)");
                    }
                }
                else if (tag.TagClass == TagClass.ContextSpecific && tag.TagValue == 2)
                {
                    string dns = names.ReadCharacterString(UniversalTagNumber.IA5String, tag);
                    Console.WriteLine($"{indent}dNSName: {dns}");
                    dnsNames.Add(dns);
                }
                else
                {
                    var encoded = names.ReadEncodedValue();
                    Console.WriteLine($"{indent}GeneralName tag [{tag.TagClass}/{tag.TagValue}]: {Convert.ToHexString(encoded.Span)}");
                }
            }
        }
        catch (AsnContentException ex)
        {
            Console.WriteLine($"{indent}SAN parse error: {ex.Message} (dump stopped; counts above are partial)");
        }

        return new ParsedSan(permanentIdentifiers, dnsNames, permanentIdentifierOtherNames);
    }
}

// The bare coclass, dynamic-dispatch only, duplicated inline per the tools/
// convention. Never declare a typed ICertRequest interface here; the ADCS COM
// dispatch rules in CLAUDE.md apply to tools as well.
[ComImport]
[Guid("98aff3f0-5524-11d0-8812-00a0c903b83c")]
internal class CertRequestClass
{
}

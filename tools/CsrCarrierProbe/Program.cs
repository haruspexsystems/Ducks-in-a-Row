using System.Formats.Asn1;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certus.Core.Adcs;

// Diagnostic for Certus security issue #548 (CRA risks R02 and R03) and the
// open probe question in Certus-Security #15.
//
// The product's finalize identifier check reads subject alternative names from
// exactly one CSR carrier: the first value of the PKCS#9 extensionRequest
// attribute (1.2.840.113549.1.9.14). It skips every other attribute and any
// second value of extensionRequest without refusing them. The Microsoft world
// has other carriers, so the live question this probe answers is: if a CSR
// carries a SAN, or requests a dangerous Application Policy, through a carrier
// the parser never looks at, does ADCS honour it on an enrollee supplies
// subject template and put it in the issued certificate?
//
// Following the project rule that a runtime fact about ADCS is probed rather
// than guessed (AdcsQiProbe, DeviceAttestProbe), this submits several CSRs to a
// live CA and, for each one the CA issues, re-parses the issued certificate and
// prints a verdict line. certutil is not a witness here: it takes a different
// route to the CA than the managed ICertRequest::Submit path the product uses,
// so this probe submits through that same managed path.
//
// The runs, each against one enrollee supplies subject template:
//
//   Control: a well formed PKCS#9 extensionRequest carrying a dNSName SAN. It
//            proves the template issues and that the CA honours a SAN from the
//            standard carrier, so a "no SAN" result on the smuggling runs means
//            the carrier was ignored and not that the template drops all SANs.
//   Run 1:   the SAN (a dNSName plus a UPN otherName) carried under
//            szOID_CERT_EXTENSIONS (1.3.6.1.4.1.311.2.1.14) in place of the
//            PKCS#9 OID. The ESC1 shape: a UPN the identifier check never saw.
//   Run 2:   a SAN requested through the enrolment name and value pair attribute
//            (1.3.6.1.4.1.311.13.2.1), the "SAN" name/value form. Expected inert
//            unless the CA has EDITF_ATTRIBUTESUBJECTALTNAME2 set, which must
//            never be enabled; the probe refuses to be the thing that sets it.
//   Run 3:   two values in the PKCS#9 extensionRequest SET: the first a
//            legitimate SAN matching the CN, the second a smuggled dNSName. The
//            parser reads only the first value.
//   Run 4:   requested Application Policies (1.3.6.1.4.1.311.21.10) asking for
//            smart card logon, through the standard extensionRequest carrier, on
//            a schema version 1 template such as WebServer. The ESC15 shape
//            (CVE-2024-49019): an unpatched CA copies the requested Application
//            Policies into the certificate and Windows honours them over the EKU.
//
// This probe never sends the cdc or rmd attributes of CVE-2026-54121, and never
// enables EDITF_ATTRIBUTESUBJECTALTNAME2. It submits benign names the operator
// controls, to a template on a lab CA, to answer the passthrough question only.
//
// Configuration comes from the environment, matching the other probes:
//   CERTUS_PROBE_CA       "<host>\<CA name>"   (required)
//   CERTUS_PROBE_TEMPLATE "<template name>"    (required; an enrollee supplies
//                          subject template the probe account may enroll on,
//                          ideally schema version 1 such as WebServer for Run 4)

Console.WriteLine("Certus CsrCarrierProbe — CSR attribute carrier passthrough diagnostic (issue #548)");
Console.WriteLine($"Process: PID={Environment.ProcessId}, User={Environment.UserDomainName}\\{Environment.UserName}, Bitness={(IntPtr.Size == 8 ? "x64" : "x86")}");
Console.WriteLine();

string? caConfig = Environment.GetEnvironmentVariable("CERTUS_PROBE_CA");
string? template = Environment.GetEnvironmentVariable("CERTUS_PROBE_TEMPLATE");
if (string.IsNullOrWhiteSpace(caConfig) || string.IsNullOrWhiteSpace(template))
{
    Console.WriteLine("Skipped: set CERTUS_PROBE_CA=\"<host>\\<CA name>\" and CERTUS_PROBE_TEMPLATE=\"<template>\" to enable.");
    return;
}

// The template name is operator supplied, so check it once here with the same
// guard the product submits through, before several runs fail identically. This
// is also what keeps the probe from being the one place that hands a live CA an
// unchecked request attribute string (issue #175, CVE-2026-54121).
if (!AdcsRequestAttributes.TryValidateTemplateName(template, out var templateError))
{
    Console.WriteLine($"Skipped: {templateError}");
    return;
}

Console.WriteLine($"CA config: {caConfig}");
Console.WriteLine($"Template:  {template}");
Console.WriteLine();
Console.WriteLine("This probe submits benign names the operator controls to answer the passthrough");
Console.WriteLine("question. It never sends cdc/rmd and never enables EDITF_ATTRIBUTESUBJECTALTNAME2.");
Console.WriteLine();

var runs = new (string Label, Func<RSA, byte[]> Build, Action<X509Certificate2> Report)[]
{
    ("Control: dNSName SAN in the standard extensionRequest",
        key => CsrBuilder.SanOnly(key, "carrier-probe-cn.probe.local",
            SanBuilder.Dns("carrier-probe-cn.probe.local")),
        cert => CarrierReport.ReportSan(cert,
            expectDns: "carrier-probe-cn.probe.local", expectUpn: null)),

    ("Run 1: SAN (dNSName + UPN otherName) under szOID_CERT_EXTENSIONS",
        key => CsrBuilder.CustomExtensionCarrier(key, "carrier-probe-cn.probe.local",
            CsrBuilder.SzOidCertExtensions,
            SanBuilder.DnsAndUpn("smuggled-msext.probe.local", "victim@probe.local")),
        cert => CarrierReport.ReportSan(cert,
            expectDns: "smuggled-msext.probe.local", expectUpn: "victim@probe.local")),

    ("Run 2: SAN through the enrolment name and value pair attribute",
        key => CsrBuilder.NameValuePairCarrier(key, "carrier-probe-cn.probe.local",
            ("SAN", "dns=smuggled-nvp.probe.local")),
        cert => CarrierReport.ReportSan(cert,
            expectDns: "smuggled-nvp.probe.local", expectUpn: null)),

    ("Run 3: smuggled dNSName in a second extensionRequest value",
        key => CsrBuilder.SecondExtensionRequestValue(key, "carrier-probe-cn.probe.local",
            SanBuilder.Dns("carrier-probe-cn.probe.local"),
            SanBuilder.Dns("smuggled-second.probe.local")),
        cert => CarrierReport.ReportSan(cert,
            expectDns: "smuggled-second.probe.local", expectUpn: null)),

    ("Run 4: requested Application Policies (smart card logon) in extensionRequest",
        key => CsrBuilder.SanPlusExtension(key, "carrier-probe-cn.probe.local",
            SanBuilder.Dns("carrier-probe-cn.probe.local"),
            ExtensionBuilder.ApplicationPolicies(CarrierReport.SmartCardLogonOid)),
        cert => CarrierReport.ReportApplicationPolicies(cert, CarrierReport.SmartCardLogonOid)),
};

foreach (var run in runs)
{
    Console.WriteLine($"=== {run.Label} ===");
    try
    {
        byte[] csrDer = run.Build(RSA.Create(2048));
        Submission.Execute(caConfig, template, csrDer, run.Report);
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

internal static class Submission
{
    // ICertRequest::Submit flags and dispositions, duplicated inline per the
    // tools/ convention so the probe stays standalone and never links
    // Certus.Adcs.
    private const int EncodingBase64 = 0x1;
    private const int FormatPkcs10 = 0x100;
    private const int OutputBase64 = 0x1;

    private const int DispositionDenied = 0x2;
    private const int DispositionIssued = 0x3;
    private const int DispositionIssuedOutOfBand = 0x4;
    private const int DispositionUnderSubmission = 0x5;

    public static void Execute(string caConfig, string template, byte[] csrDer, Action<X509Certificate2> report)
    {
        string csrBase64 = Convert.ToBase64String(csrDer);

        var certRequest = new CertRequestClass();
        dynamic d = certRequest;
        try
        {
            // The template attribute is built through the product's own guard,
            // never interpolated here.
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
                    using (var cert = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(certBase64)))
                    {
                        Console.WriteLine($"  Issued: serial {cert.SerialNumber}, subject {cert.Subject}");
                        report(cert);
                    }
                    break;

                case DispositionUnderSubmission:
                    Console.WriteLine("  Verdict: PENDING — the template requires manager approval, so this template");
                    Console.WriteLine("  cannot answer the passthrough question. Pick one that auto issues.");
                    break;

                case DispositionDenied:
                    Console.WriteLine("  Verdict: DENIED — a denial is itself an answer here: the CA refused rather");
                    Console.WriteLine("  than honouring the carrier. Read the disposition message and the CA failed");
                    Console.WriteLine("  request log for the request id above to tell a permissions denial from a");
                    Console.WriteLine("  malformed request refusal.");
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

    private static string DispositionName(int disposition) => disposition switch
    {
        0 => "Incomplete",
        0x1 => "Error",
        DispositionDenied => "Denied",
        DispositionIssued => "Issued",
        DispositionIssuedOutOfBand => "IssuedOutOfBand",
        DispositionUnderSubmission => "UnderSubmission",
        6 => "Revoked",
        _ => "Unknown",
    };
}

internal static class CarrierReport
{
    private const string SubjectAltNameOid = "2.5.29.17";
    private const string EnhancedKeyUsageOid = "2.5.29.37";
    internal const string ApplicationPoliciesOid = "1.3.6.1.4.1.311.21.10";
    internal const string SmartCardLogonOid = "1.3.6.1.4.1.311.20.2.2";

    public static void ReportSan(X509Certificate2 cert, string? expectDns, string? expectUpn)
    {
        var sanExtension = cert.Extensions[SubjectAltNameOid];
        if (sanExtension == null)
        {
            Console.WriteLine("  Issued certificate has NO SubjectAltName extension.");
            Console.WriteLine("  CARRIER HONOURED: no (the CA did not read a SAN from this carrier)");
            return;
        }

        Console.WriteLine("  Issued certificate SAN:");
        var names = GeneralNameDump.Dump(sanExtension.RawData, "    ");

        bool dnsHit = expectDns != null &&
            names.DnsNames.Contains(expectDns, StringComparer.OrdinalIgnoreCase);
        bool upnHit = expectUpn != null &&
            names.Upns.Contains(expectUpn, StringComparer.OrdinalIgnoreCase);

        if (dnsHit || upnHit)
        {
            Console.WriteLine("  CARRIER HONOURED: YES — content the product's parser never read reached the");
            Console.WriteLine($"  issued certificate. dNSName '{expectDns}' present: {dnsHit}. UPN '{expectUpn}' present: {upnHit}.");
        }
        else
        {
            Console.WriteLine("  CARRIER HONOURED: no (the expected smuggled name is not in the issued SAN)");
        }
    }

    public static void ReportApplicationPolicies(X509Certificate2 cert, string requestedOid)
    {
        var ekuExtension = cert.Extensions[EnhancedKeyUsageOid];
        if (ekuExtension is X509EnhancedKeyUsageExtension eku)
        {
            var oids = eku.EnhancedKeyUsages.Cast<Oid>().Select(o => o.Value).ToList();
            Console.WriteLine($"  Issued EKU (2.5.29.37): {string.Join(", ", oids)}");
        }
        else
        {
            Console.WriteLine("  Issued certificate has NO EKU extension.");
        }

        var appPolicyExtension = cert.Extensions[ApplicationPoliciesOid];
        List<string> appPolicyOids = new();
        if (appPolicyExtension != null)
        {
            appPolicyOids = ReadApplicationPolicyOids(appPolicyExtension.RawData);
            Console.WriteLine($"  Issued Application Policies (1.3.6.1.4.1.311.21.10): {string.Join(", ", appPolicyOids)}");
        }
        else
        {
            Console.WriteLine("  Issued certificate has NO Application Policies extension.");
        }

        bool ekuHasIt = ekuExtension is X509EnhancedKeyUsageExtension e &&
            e.EnhancedKeyUsages.Cast<Oid>().Any(o => o.Value == requestedOid);
        bool appHasIt = appPolicyOids.Contains(requestedOid);

        if (ekuHasIt || appHasIt)
        {
            Console.WriteLine($"  ESC15 CHECK: HONOURED — the requested policy {requestedOid} reached the");
            Console.WriteLine($"  certificate (in EKU: {ekuHasIt}, in Application Policies: {appHasIt}).");
        }
        else
        {
            Console.WriteLine($"  ESC15 CHECK: not honoured (requested {requestedOid} is in neither EKU nor Application Policies)");
        }
    }

    // CERT_POLICIES ::= SEQUENCE OF PolicyInformation
    // PolicyInformation ::= SEQUENCE { policyIdentifier OID, qualifiers OPTIONAL }
    private static List<string> ReadApplicationPolicyOids(byte[] raw)
    {
        var oids = new List<string>();
        try
        {
            var reader = new AsnReader(raw, AsnEncodingRules.DER);
            var policies = reader.ReadSequence();
            while (policies.HasData)
            {
                var policy = policies.ReadSequence();
                oids.Add(policy.ReadObjectIdentifier());
                // Skip any policy qualifiers.
                while (policy.HasData) policy.ReadEncodedValue();
            }
        }
        catch (AsnContentException ex)
        {
            Console.WriteLine($"    Application Policies parse error: {ex.Message}");
        }
        return oids;
    }
}

internal sealed record ParsedGeneralNames(List<string> DnsNames, List<string> Upns);

internal static class GeneralNameDump
{
    private const string UpnOtherNameOid = "1.3.6.1.4.1.311.20.2.3";
    private const string IdOnPermanentIdentifier = "1.3.6.1.5.5.7.8.3";

    public static ParsedGeneralNames Dump(byte[] rawSan, string indent)
    {
        var dnsNames = new List<string>();
        var upns = new List<string>();

        try
        {
            var reader = new AsnReader(rawSan, AsnEncodingRules.DER);
            var names = reader.ReadSequence();
            while (names.HasData)
            {
                var tag = names.PeekTag();
                if (tag.TagClass == TagClass.ContextSpecific && tag.TagValue == 0)
                {
                    var otherName = names.ReadSequence(tag);
                    string typeId = otherName.ReadObjectIdentifier();
                    var explicitValue = otherName.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
                    if (typeId == UpnOtherNameOid)
                    {
                        string upn = explicitValue.ReadCharacterString(UniversalTagNumber.UTF8String);
                        Console.WriteLine($"{indent}otherName UPN: {upn}");
                        upns.Add(upn);
                    }
                    else if (typeId == IdOnPermanentIdentifier)
                    {
                        Console.WriteLine($"{indent}otherName PermanentIdentifier (type-id {typeId})");
                    }
                    else
                    {
                        Console.WriteLine($"{indent}otherName type-id {typeId}");
                    }
                }
                else if (tag.TagClass == TagClass.ContextSpecific && tag.TagValue == 2)
                {
                    string dns = names.ReadCharacterString(UniversalTagNumber.IA5String, tag);
                    Console.WriteLine($"{indent}dNSName: {dns}");
                    dnsNames.Add(dns);
                }
                else if (tag.TagClass == TagClass.ContextSpecific && tag.TagValue == 1)
                {
                    string rfc822 = names.ReadCharacterString(UniversalTagNumber.IA5String, tag);
                    Console.WriteLine($"{indent}rfc822Name: {rfc822}");
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
            Console.WriteLine($"{indent}SAN parse error: {ex.Message} (dump stopped)");
        }

        return new ParsedGeneralNames(dnsNames, upns);
    }
}

// Builds the SAN GeneralNames DER for the runs above.
internal static class SanBuilder
{
    private const string UpnOtherNameOid = "1.3.6.1.4.1.311.20.2.3";

    public static byte[] Dns(string dns)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
            writer.WriteCharacterString(UniversalTagNumber.IA5String, dns, new Asn1Tag(TagClass.ContextSpecific, 2));
        return writer.Encode();
    }

    public static byte[] DnsAndUpn(string dns, string upn)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteCharacterString(UniversalTagNumber.IA5String, dns, new Asn1Tag(TagClass.ContextSpecific, 2));
            // otherName [0] { type-id OID, value [0] EXPLICIT UTF8String } for a UPN.
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                writer.WriteObjectIdentifier(UpnOtherNameOid);
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                    writer.WriteCharacterString(UniversalTagNumber.UTF8String, upn);
            }
        }
        return writer.Encode();
    }
}

// Builds a single X.509 Extension's DER (extnID, extnValue OCTET STRING).
internal static class ExtensionBuilder
{
    private const string SubjectAltNameOid = "2.5.29.17";
    private const string ApplicationPoliciesOid = "1.3.6.1.4.1.311.21.10";

    public static byte[] SubjectAltName(byte[] generalNamesDer) =>
        Extension(SubjectAltNameOid, generalNamesDer);

    public static byte[] ApplicationPolicies(params string[] policyOids)
    {
        var inner = new AsnWriter(AsnEncodingRules.DER);
        using (inner.PushSequence())
        {
            foreach (var oid in policyOids)
                using (inner.PushSequence())
                    inner.WriteObjectIdentifier(oid);
        }
        return Extension(ApplicationPoliciesOid, inner.Encode());
    }

    private static byte[] Extension(string oid, byte[] extnValue)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(oid);
            writer.WriteOctetString(extnValue);
        }
        return writer.Encode();
    }

    // Extensions ::= SEQUENCE OF Extension
    public static byte[] Extensions(params byte[][] extensions)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
            foreach (var ext in extensions)
                writer.WriteEncodedValue(ext);
        return writer.Encode();
    }
}

// Builds complete, signed PKCS#10 requests. The product's parser and the other
// probes use CertificateRequest, which always carries extensions under the
// PKCS#9 extensionRequest OID; to place extensions under another attribute OID,
// or a second value, the request has to be assembled by hand.
internal static class CsrBuilder
{
    internal const string SzOidCertExtensions = "1.3.6.1.4.1.311.2.1.14";
    private const string Pkcs9ExtensionRequest = "1.2.840.113549.1.9.14";
    private const string EnrolmentNameValuePair = "1.3.6.1.4.1.311.13.2.1";
    private const string Sha256WithRsa = "1.2.840.113549.1.1.11";

    // The standard carrier, one PKCS#9 extensionRequest attribute whose single
    // value is an Extensions sequence built from the already encoded extensions.
    private static byte[] FromExtensions(RSA key, string cn, params byte[][] extensions)
    {
        byte[] extensionsDer = ExtensionBuilder.Extensions(extensions);
        return Build(key, cn, new (string, byte[][])[]
        {
            (Pkcs9ExtensionRequest, new[] { extensionsDer }),
        });
    }

    public static byte[] SanOnly(RSA key, string cn, byte[] sanGeneralNames)
        => FromExtensions(key, cn, ExtensionBuilder.SubjectAltName(sanGeneralNames));

    public static byte[] SanPlusExtension(RSA key, string cn, byte[] sanGeneralNames, byte[] extraExtension)
        => FromExtensions(key, cn, ExtensionBuilder.SubjectAltName(sanGeneralNames), extraExtension);

    public static byte[] CustomExtensionCarrier(RSA key, string cn, string attributeOid, byte[] sanGeneralNames)
    {
        byte[] extensionsDer = ExtensionBuilder.Extensions(ExtensionBuilder.SubjectAltName(sanGeneralNames));
        return Build(key, cn, new (string, byte[][])[]
        {
            (attributeOid, new[] { extensionsDer }),
        });
    }

    public static byte[] SecondExtensionRequestValue(RSA key, string cn, byte[] firstSan, byte[] secondSan)
    {
        byte[] firstExtensions = ExtensionBuilder.Extensions(ExtensionBuilder.SubjectAltName(firstSan));
        byte[] secondExtensions = ExtensionBuilder.Extensions(ExtensionBuilder.SubjectAltName(secondSan));
        return Build(key, cn, new (string, byte[][])[]
        {
            (Pkcs9ExtensionRequest, new[] { firstExtensions, secondExtensions }),
        });
    }

    public static byte[] NameValuePairCarrier(RSA key, string cn, params (string Name, string Value)[] pairs)
    {
        var values = new List<byte[]>();
        foreach (var (name, value) in pairs)
        {
            var writer = new AsnWriter(AsnEncodingRules.DER);
            using (writer.PushSequence())
            {
                writer.WriteCharacterString(UniversalTagNumber.BMPString, name);
                writer.WriteCharacterString(UniversalTagNumber.BMPString, value);
            }
            values.Add(writer.Encode());
        }
        return Build(key, cn, new (string, byte[][])[]
        {
            (EnrolmentNameValuePair, values.ToArray()),
        });
    }

    // CertificationRequest ::= SEQUENCE { info, signatureAlgorithm, signature }
    private static byte[] Build(RSA key, string cn, (string Oid, byte[][] Values)[] attributes)
    {
        byte[] subject = new X500DistinguishedName($"CN={cn}").RawData;
        byte[] spki = key.ExportSubjectPublicKeyInfo();

        var infoWriter = new AsnWriter(AsnEncodingRules.DER);
        using (infoWriter.PushSequence())
        {
            infoWriter.WriteInteger(0);
            infoWriter.WriteEncodedValue(subject);
            infoWriter.WriteEncodedValue(spki);
            // attributes [0] IMPLICIT SET OF Attribute
            using (infoWriter.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                foreach (var (oid, values) in attributes)
                {
                    using (infoWriter.PushSequence())
                    {
                        infoWriter.WriteObjectIdentifier(oid);
                        using (infoWriter.PushSetOf())
                            foreach (var value in values)
                                infoWriter.WriteEncodedValue(value);
                    }
                }
            }
        }

        byte[] info = infoWriter.Encode();
        byte[] signature = key.SignData(info, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteEncodedValue(info);
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(Sha256WithRsa);
                writer.WriteNull();
            }
            writer.WriteBitString(signature);
        }
        return writer.Encode();
    }
}

// The bare coclass, dynamic dispatch only, duplicated inline per the tools/
// convention. Never declare a typed ICertRequest interface here; the ADCS COM
// dispatch rules in CLAUDE.md apply to tools as well.
[ComImport]
[Guid("98aff3f0-5524-11d0-8812-00a0c903b83c")]
internal class CertRequestClass
{
}

using System.Formats.Asn1;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Certus.Adcs.Crl;
using Certus.Core.Crl;

/// <summary>
/// Issue #447: what a CA will tell us about its CRLs, and whether the product's
/// own readers understand what comes back.
///
/// Nothing in the product read a CRL before this, so every line below is an open
/// question rather than a regression check. The ones that decide the design:
///
///   1. Do the CRL properties dispatch by name at all, the way the chain read
///      already does (CR_PROP_CASIGCERTCHAIN through the same coclass)?
///   2. Does CR_PROP_CASIGCERTCRLCHAIN (32) carry the CRLs of the CA's PARENTS?
///      MS-WCCE section 3.2.1.4.3.2.33 says a CA asked for a chain with CRLs
///      fetches each one from that certificate's own distribution points, which
///      would mean the offline root's CRL is reachable over the COM channel we
///      already hold. The issue asserts the opposite. A single tier lab cannot
///      settle it, because there is no parent, but it can show what the property
///      returns and whether it works at all.
///   3. Is the CA database's CRL table reachable through ICertView2::SetTable?
///      It holds the numbers, the dates and the publish status per CA key
///      without transferring a CRL that can be megabytes.
///   4. Can this host read the CA's own published CRL back out of the
///      distribution points the CA writes into certificates?
///
/// The readers under question 4 are the product's own files, linked into this
/// project rather than copied (see the csproj), so a lab run exercises the code
/// that will ship and not an imitation of it.
/// </summary>
internal static class CrlProbe
{
    private static readonly Guid CertRequestClsid = new("98aff3f0-5524-11d0-8812-00a0c903b83c");
    private static readonly Guid CertViewClsid = new("a12d0f7a-1e84-11d1-9bd6-00c04fb683fa");

    // CR_PROP ids from certcli.h, and the two the CA database answers with.
    private const int CaSigCertCount = 11;
    private const int CaSigCert = 12;
    private const int CaSigCertChain = 13;
    private const int BaseCrl = 17;
    private const int DeltaCrl = 18;
    private const int CrlState = 20;
    private const int BaseCrlPublishStatus = 30;
    private const int DeltaCrlPublishStatus = 31;
    private const int CaSigCertCrlChain = 32;
    private const int CertCdpUrls = 41;
    private const int CrlPartitionCount = 46;

    private const int PropTypeLong = 1;
    private const int PropTypeBinary = 3;
    private const int PropTypeString = 4;
    private const int OutBase64 = 1;

    /// <summary>CVRC_TABLE_CRL.</summary>
    private const int CrlTable = 0x5000;

    private const int SchemaColumn = 0;

    /// <summary>CV_OUT_BINARY. Ignored for the long and date columns selected here.</summary>
    private const int EncodingBinary = 0x2;

    /// <summary>
    /// Every column MS-CSRA requires of a CRL table. Each is resolved on its own
    /// so one unknown name reports itself rather than killing the pass.
    /// </summary>
    private static readonly string[] CrlColumns =
    [
        "CRLRowId",
        "CRLNumber",
        "CRLNameId",
        "CRLMinBase",
        "CRLCount",
        "CRLThisUpdate",
        "CRLNextUpdate",
        "CRLThisPublish",
        "CRLNextPublish",
        "CRLPublishStatusCode",
        "CRLPublishFlags",
        "CRLPropagationComplete",
    ];

    /// <summary>A CA that has been renewed many times still only needs a few of these.</summary>
    private const int MaxKeyIndexes = 4;

    /// <summary>The timeouts the product will use, so the lab measures what ships.</summary>
    private static readonly TimeSpan FetchTimeout = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan LdapServerTimeLimit = TimeSpan.FromSeconds(10);
    private const int MaxCrlBytes = 32 * 1024 * 1024;

    public static void Run(string caConfig)
    {
        var signingCertificate = RunProperties(caConfig);
        RunCrlTable(caConfig);
        RunDistributionPoints(caConfig, signingCertificate);
        signingCertificate?.Dispose();
    }

    /// <summary>
    /// The GetCAProperty half. Returns the CA's current signing certificate when
    /// it could be read, because the distribution point pass needs it to verify
    /// what it fetches.
    /// </summary>
    private static X509Certificate2? RunProperties(string caConfig)
    {
        Console.WriteLine();
        Console.WriteLine("  --- GetCAProperty ---");

        object? raw = null;
        X509Certificate2? signingCertificate = null;
        try
        {
            raw = Activator.CreateInstance(Type.GetTypeFromCLSID(CertRequestClsid)!);
            dynamic request = raw!;

            var count = 0;
            var countValue = ReadProperty(
                request, caConfig, "CR_PROP_CASIGCERTCOUNT (11)",
                CaSigCertCount, 0, PropTypeLong, 0);
            if (countValue is int parsedCount)
            {
                count = parsedCount;
                Console.WriteLine($"    Signing certificates: {count}");
            }

            if (count <= 0)
            {
                Console.WriteLine("    Cannot continue without a signing certificate count.");
                return null;
            }

            var indexes = Math.Min(count, MaxKeyIndexes);
            for (var index = 0; index < indexes; index++)
            {
                Console.WriteLine();
                Console.WriteLine($"    Key index {index}:");

                ReportLong(request, caConfig, "CR_PROP_CRLSTATE (20)", CrlState, index);
                ReportCrl(request, caConfig, "CR_PROP_BASECRL (17)", BaseCrl, index);
                ReportCrl(request, caConfig, "CR_PROP_DELTACRL (18)", DeltaCrl, index);
                ReportPublishStatus(
                    request, caConfig, "CR_PROP_BASECRLPUBLISHSTATUS (30)", BaseCrlPublishStatus, index);
                ReportPublishStatus(
                    request, caConfig, "CR_PROP_DELTACRLPUBLISHSTATUS (31)", DeltaCrlPublishStatus, index);
                ReportUrls(request, caConfig, "CR_PROP_CERTCDPURLS (41)", CertCdpUrls, index);
                ReportChainWithCrls(request, caConfig, index);
            }

            Console.WriteLine();
            ReportLong(request, caConfig, "CR_PROP_CRLPARTITIONCOUNT (46)", CrlPartitionCount, 0);

            // The current signing certificate, for the verification the
            // distribution point pass does.
            var certValue = ReadProperty(
                request, caConfig, $"CR_PROP_CASIGCERT (12), index {count - 1}",
                CaSigCert, count - 1, PropTypeBinary, OutBase64);
            if (certValue is string certBase64 && TryDecodeBase64(certBase64, out var certDer))
            {
                signingCertificate = LoadCertificate(certDer);
                Console.WriteLine($"      subject: {signingCertificate.Subject}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"    FAIL — {ex.GetType().Name}: 0x{Marshal.GetHRForException(ex):X8} {ex.Message}");
        }
        finally
        {
            if (raw != null && Marshal.IsComObject(raw))
                Marshal.FinalReleaseComObject(raw);
        }

        return signingCertificate;
    }

    /// <summary>
    /// The CA database's CRL table. Enumerating the schema first answers what the
    /// columns are really called on this build, the way the column name probe
    /// does for the request table: GetColumnIndex takes an unqualified name and
    /// GetName hands back the canonical one, and they are not always the same.
    /// </summary>
    private static void RunCrlTable(string caConfig)
    {
        Console.WriteLine();
        Console.WriteLine("  --- CertView, CRL table (CVRC_TABLE_CRL 0x5000) ---");

        object? raw = null;
        object? rowEnum = null;
        try
        {
            raw = Activator.CreateInstance(Type.GetTypeFromCLSID(CertViewClsid)!);
            dynamic view = raw!;
            view.OpenConnection(caConfig);

            try
            {
                view.SetTable(CrlTable);
                Console.WriteLine("    SetTable(0x5000) -> OK");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"    SetTable(0x5000) -> FAIL {ex.GetType().Name} 0x{Marshal.GetHRForException(ex):X8} {ex.Message}");
                Console.WriteLine("    (the CRL table is not reachable this way; the properties above are the fallback)");
                return;
            }

            ReportSchema(view);

            var resolved = new List<int>(CrlColumns.Length);
            foreach (var column in CrlColumns)
            {
                try
                {
                    int index = (int)view.GetColumnIndex(SchemaColumn, column);
                    resolved.Add(index);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"    GetColumnIndex(Schema, \"{column}\") -> FAILED {ex.GetType().Name} 0x{Marshal.GetHRForException(ex):X8}");
                }
            }

            if (resolved.Count == 0)
            {
                Console.WriteLine("    No CRL column resolved, so there is nothing to select.");
                return;
            }

            view.SetResultColumnCount(resolved.Count);
            foreach (var index in resolved)
                view.SetResultColumn(index);

            rowEnum = view.OpenView();
            dynamic rows = rowEnum!;

            var rowNumber = 0;
            while (rowNumber < MaxKeyIndexes * 2 && (int)rows.Next() != -1)
            {
                rowNumber++;
                Console.WriteLine($"    Row {rowNumber}:");

                object? columnEnumObject = null;
                try
                {
                    columnEnumObject = rows.EnumCertViewColumn();
                    dynamic columns = columnEnumObject!;
                    while ((int)columns.Next() != -1)
                    {
                        string name = (string)columns.GetName();
                        object? value = columns.GetValue(EncodingBinary);
                        Console.WriteLine(
                            $"      {name,-24} {Describe(value)}");
                    }
                }
                finally
                {
                    if (columnEnumObject != null && Marshal.IsComObject(columnEnumObject))
                        Marshal.FinalReleaseComObject(columnEnumObject);
                }
            }

            if (rowNumber == 0)
                Console.WriteLine("    The CRL table returned no rows, which a CA that has published a CRL should not do.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"    FAIL — {ex.GetType().Name}: 0x{Marshal.GetHRForException(ex):X8} {ex.Message}");
        }
        finally
        {
            if (rowEnum != null && Marshal.IsComObject(rowEnum)) Marshal.FinalReleaseComObject(rowEnum);
            if (raw != null && Marshal.IsComObject(raw)) Marshal.FinalReleaseComObject(raw);
        }
    }

    /// <summary>
    /// Reads the CA's own CRL back out of the places the CA publishes it, with
    /// the product's readers and fetchers, and then reads the CA certificate's
    /// own distribution points. On a two tier CA the second of those is where
    /// the offline root's CRL lives, which is the whole point of issue #447.
    /// </summary>
    private static void RunDistributionPoints(string caConfig, X509Certificate2? signingCertificate)
    {
        Console.WriteLine();
        Console.WriteLine("  --- Distribution points, read with the product's own readers ---");

        if (signingCertificate is null)
        {
            Console.WriteLine("    Skipped: the CA signing certificate could not be read above.");
            return;
        }

        var own = ReadCdpUrls(caConfig);
        if (own.Count == 0)
        {
            Console.WriteLine("    The CA publishes no distribution point URL for its own CRL.");
        }
        else
        {
            Console.WriteLine("    The CA's own CRL, at the URLs it writes into the certificates it issues:");
            foreach (var url in own)
                FetchAndReport(url, signingCertificate);
        }

        Console.WriteLine();
        var parents = CdpExtensionReader.ReadFrom(signingCertificate);
        if (parents.Urls.Count == 0)
        {
            Console.WriteLine("    The CA's own certificate names no distribution point.");
            Console.WriteLine("    That is the expected shape for a self signed root, and it is also why a");
            Console.WriteLine("    single tier lab cannot answer the offline root question: there is no parent.");
        }
        else
        {
            // The parent's certificate comes from the chain the product already
            // reads, so a two tier CA gets the whole answer in one run: the
            // root's CRL fetched from the distribution point named on the CA's
            // own certificate, and verified against the root that signed it.
            using var issuer = ReadIssuerCertificate(caConfig, signingCertificate);
            Console.WriteLine(issuer is null
                ? "    The CRL that covers the CA's own certificate (the issuer's certificate was not found, so it is not verified):"
                : $"    The CRL that covers the CA's own certificate, issued by {issuer.Subject}:");

            foreach (var url in parents.Urls)
                FetchAndReport(url, issuer);
        }

        if (parents.SkippedIndirect > 0 || parents.SkippedRelativeName > 0)
        {
            Console.WriteLine(
                $"    Skipped {parents.SkippedIndirect} indirect and {parents.SkippedRelativeName} relative name distribution point(s).");
        }
    }

    /// <summary>
    /// The certificate of the CA that issued this CA's own certificate, out of
    /// CR_PROP_CASIGCERTCHAIN (13), which is the property
    /// AdcsClient.ReadCaCertificateChain already uses. Null on a single tier CA,
    /// where the only certificate in the chain is the signing certificate
    /// itself.
    /// </summary>
    private static X509Certificate2? ReadIssuerCertificate(
        string caConfig, X509Certificate2 signingCertificate)
    {
        object? raw = null;
        try
        {
            raw = Activator.CreateInstance(Type.GetTypeFromCLSID(CertRequestClsid)!);
            dynamic request = raw!;
            var value = request.GetCAProperty(caConfig, CaSigCertChain, -1, PropTypeBinary, OutBase64);
            if (value is not string base64
                || !TryDecodeBase64(base64, out var pkcs7)
                || !TryReadPkcs7(pkcs7, out var certificates, out _, out _))
            {
                return null;
            }

            foreach (var der in certificates)
            {
                var candidate = LoadCertificate(der);
                if (candidate.SubjectName.RawData.AsSpan()
                        .SequenceEqual(signingCertificate.IssuerName.RawData)
                    && !candidate.SubjectName.RawData.AsSpan()
                        .SequenceEqual(signingCertificate.SubjectName.RawData))
                {
                    return candidate;
                }

                candidate.Dispose();
            }

            return null;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"    CR_PROP_CASIGCERTCHAIN -> FAIL {ex.GetType().Name} 0x{Marshal.GetHRForException(ex):X8}");
            return null;
        }
        finally
        {
            if (raw != null && Marshal.IsComObject(raw))
                Marshal.FinalReleaseComObject(raw);
        }
    }

    private static List<string> ReadCdpUrls(string caConfig)
    {
        var urls = new List<string>();
        object? raw = null;
        try
        {
            raw = Activator.CreateInstance(Type.GetTypeFromCLSID(CertRequestClsid)!);
            dynamic request = raw!;
            var value = request.GetCAProperty(caConfig, CertCdpUrls, -1, PropTypeString, 0);
            if (value is string text)
                urls.AddRange(SplitUrls(text));
        }
        catch (Exception ex)
        {
            Console.WriteLine($"    CR_PROP_CERTCDPURLS -> FAIL {ex.GetType().Name} 0x{Marshal.GetHRForException(ex):X8}");
        }
        finally
        {
            if (raw != null && Marshal.IsComObject(raw))
                Marshal.FinalReleaseComObject(raw);
        }

        return urls;
    }

    private static void FetchAndReport(string url, X509Certificate2? issuer)
    {
        Console.WriteLine($"      {url}");

        CrlFetchResult result;
        if (LdapCdpUrl.TryParse(url, out var ldap, out _))
        {
            result = LdapCrlFetcher.Fetch(ldap!, FetchTimeout, LdapServerTimeLimit);
        }
        else if (Uri.TryCreate(url, UriKind.Absolute, out var uri)
                 && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps))
        {
            using var client = new HttpClient { Timeout = FetchTimeout };
            var fetcher = new HttpCrlFetcher(client);
            result = fetcher.FetchAsync(uri, MaxCrlBytes, null, null).GetAwaiter().GetResult();
        }
        else
        {
            Console.WriteLine("        (no fetcher for this scheme; file and ftp are out of scope)");
            return;
        }

        if (!result.Ok)
        {
            Console.WriteLine($"        NOT READ: {result.Error}");
            return;
        }

        Console.WriteLine($"        read {result.Crls.Count} CRL(s)");
        foreach (var crl in result.Crls)
            ReportCrlBytes(crl, issuer, "        ");
    }

    private static void ReportCrlBytes(byte[] der, X509Certificate2? issuer, string indent)
    {
        if (!CrlHeaderReader.TryRead(der, out var header, out var error))
        {
            Console.WriteLine($"{indent}{der.Length} bytes, NOT A CRL: {error}");
            return;
        }

        Console.WriteLine(
            $"{indent}{der.Length} bytes  number={header!.CrlNumberHex ?? "(none)"}  "
            + $"{(header.IsDelta ? "delta" : "base")}");
        Console.WriteLine($"{indent}  issuer      {header.IssuerName}");
        Console.WriteLine($"{indent}  thisUpdate  {header.ThisUpdate:u}");
        Console.WriteLine($"{indent}  nextUpdate  {(header.NextUpdate is null ? "(none)" : header.NextUpdate.Value.ToString("u"))}");
        Console.WriteLine($"{indent}  nextPublish {(header.NextPublish is null ? "(no Microsoft extension)" : header.NextPublish.Value.ToString("u"))}");
        Console.WriteLine($"{indent}  authority   {header.AuthorityKeyIdentifierHex ?? "(none)"}");

        if (header.NextUpdate is not null && header.NextPublish is not null)
        {
            var overlap = header.NextUpdate.Value - header.NextPublish.Value;
            var window = header.NextUpdate.Value - header.ThisUpdate;
            Console.WriteLine(
                $"{indent}  window      {window.TotalHours:F1} h, overlap {overlap.TotalHours:F1} h");
        }

        if (issuer is not null)
        {
            Console.WriteLine($"{indent}  issuer name matches the CA certificate: {CrlSignatureVerifier.MatchesIssuer(header, issuer)}");
            Console.WriteLine($"{indent}  signature: {CrlSignatureVerifier.Verify(header, issuer)}");
        }
    }

    #region GetCAProperty helpers

    private static object? ReadProperty(
        dynamic request, string caConfig, string label, int propertyId, int index, int propertyType, int flags)
    {
        try
        {
            object? value = request.GetCAProperty(caConfig, propertyId, index, propertyType, flags);
            Console.WriteLine($"      {label,-38} -> {Describe(value)}");
            return value;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"      {label,-38} -> FAIL {ex.GetType().Name} 0x{Marshal.GetHRForException(ex):X8} {ex.Message}");
            return null;
        }
    }

    private static void ReportLong(dynamic request, string caConfig, string label, int propertyId, int index) =>
        ReadProperty(request, caConfig, label, propertyId, index, PropTypeLong, 0);

    private static void ReportPublishStatus(
        dynamic request, string caConfig, string label, int propertyId, int index)
    {
        var value = ReadProperty(request, caConfig, label, propertyId, index, PropTypeLong, 0);
        if (value is int flags)
            Console.WriteLine($"        flags: {DescribePublishFlags(flags)}");
    }

    private static void ReportCrl(
        dynamic request, string caConfig, string label, int propertyId, int index)
    {
        var value = ReadProperty(request, caConfig, label, propertyId, index, PropTypeBinary, OutBase64);
        if (value is string base64 && TryDecodeBase64(base64, out var der))
            ReportCrlBytes(der, issuer: null, "        ");
    }

    private static void ReportUrls(
        dynamic request, string caConfig, string label, int propertyId, int index)
    {
        var value = ReadProperty(request, caConfig, label, propertyId, index, PropTypeString, 0);
        if (value is not string text)
            return;

        foreach (var url in SplitUrls(text))
            Console.WriteLine($"        {url}");
    }

    /// <summary>
    /// The question the design turns on. A CA that returns its parents' CRLs
    /// here has already fetched them from their distribution points on our
    /// behalf, which would mean the offline root's CRL needs no new outbound
    /// traffic from the server running this product.
    /// </summary>
    private static void ReportChainWithCrls(dynamic request, string caConfig, int index)
    {
        var value = ReadProperty(
            request, caConfig, "CR_PROP_CASIGCERTCRLCHAIN (32)",
            CaSigCertCrlChain, index, PropTypeBinary, OutBase64);

        if (value is not string base64 || !TryDecodeBase64(base64, out var pkcs7))
            return;

        if (!TryReadPkcs7(pkcs7, out var certificates, out var crls, out var error))
        {
            Console.WriteLine($"        the PKCS#7 could not be read: {error}");
            return;
        }

        Console.WriteLine($"        {certificates.Count} certificate(s), {crls.Count} CRL(s)");
        foreach (var certificate in certificates)
        {
            using var parsed = LoadCertificate(certificate);
            Console.WriteLine($"          cert: {parsed.Subject}");
        }

        foreach (var crl in crls)
            ReportCrlBytes(crl, issuer: null, "          ");

        Console.WriteLine(
            certificates.Count <= 1
                ? "        ANSWER (partial): one certificate, so this CA is its own root and the property"
                  + " cannot show whether a parent CRL would be carried."
                : $"        ANSWER: the chain holds {certificates.Count} certificates and {crls.Count} CRLs."
                  + " Compare the CRL issuers above against the certificate subjects: a CRL issued by the"
                  + " parent means the offline root's CRL arrives over COM.");
    }

    #endregion

    #region Encoding helpers

    /// <summary>
    /// Pulls the certificates and CRLs out of a PKCS#7 SignedData. Written here
    /// rather than with SignedCms because System.Security.Cryptography.Pkcs is
    /// not in the shared framework and this tool carries no product references
    /// beyond linked source. Internal because RightsProbe counts the CA chain's
    /// certificates with it (issue #469).
    /// </summary>
    internal static bool TryReadPkcs7(
        byte[] pkcs7,
        out List<byte[]> certificates,
        out List<byte[]> crls,
        out string? error)
    {
        certificates = [];
        crls = [];
        error = null;

        try
        {
            var reader = new AsnReader(pkcs7, AsnEncodingRules.BER);
            var contentInfo = reader.ReadSequence();
            contentInfo.ReadObjectIdentifier();

            var explicitContent = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            var signedData = explicitContent.ReadSequence();

            signedData.ReadEncodedValue();  // version
            signedData.ReadEncodedValue();  // digestAlgorithms
            signedData.ReadEncodedValue();  // encapContentInfo

            var certificatesTag = new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true);
            var crlsTag = new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true);

            if (signedData.HasData && signedData.PeekTag() == certificatesTag)
            {
                var set = signedData.ReadSetOf(certificatesTag);
                while (set.HasData)
                    certificates.Add(set.ReadEncodedValue().ToArray());
            }

            if (signedData.HasData && signedData.PeekTag() == crlsTag)
            {
                var set = signedData.ReadSetOf(crlsTag);
                while (set.HasData)
                    crls.Add(set.ReadEncodedValue().ToArray());
            }

            return true;
        }
        catch (AsnContentException ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private static IEnumerable<string> SplitUrls(string value) =>
        value.Split(['\n', '\r'], StringSplitOptions.RemoveEmptyEntries)
             .Select(line => line.Trim())
             .Where(line => line.Length > 0);

    private static bool TryDecodeBase64(string value, out byte[] der)
    {
        try
        {
            der = Convert.FromBase64String(value);
            return der.Length > 0;
        }
        catch (FormatException)
        {
            der = [];
            Console.WriteLine("        the value is not base64");
            return false;
        }
    }

    private static X509Certificate2 LoadCertificate(byte[] der)
    {
        // X509CertificateLoader arrived in .NET 9 and the constructor it replaces
        // is obsolete from then on, so each target uses the one it has.
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadCertificate(der);
#else
        return new X509Certificate2(der);
#endif
    }

    private static string Describe(object? value) => value switch
    {
        null => "null",
        int i => $"Int32(0x{(uint)i:X8}, signed {i})",
        string s when s.Length > 60 => $"string(length={s.Length})",
        string s => $"\"{s}\"",
        DateTime d => $"DateTime({d:u})",
        byte[] b => $"byte[{b.Length}]",
        _ => value.GetType().Name,
    };

    /// <summary>The CPF_ flags MS-CSRA defines for a CRL publish status.</summary>
    private static string DescribePublishFlags(int flags)
    {
        if (flags == 0)
            return "none";

        var names = new List<string>();
        void Check(int bit, string name)
        {
            if ((flags & bit) != 0) names.Add(name);
        }

        Check(0x1, "CPF_BASE");
        Check(0x2, "CPF_DELTA");
        Check(0x4, "CPF_COMPLETE");
        Check(0x8, "CPF_SHADOW");
        Check(0x10, "CPF_CASTORE_ERROR");
        Check(0x20, "CPF_BADURL_ERROR");
        Check(0x40, "CPF_MANUAL");
        Check(0x80, "CPF_SIGNATURE_ERROR");
        Check(0x100, "CPF_LDAP_ERROR");
        Check(0x200, "CPF_FILE_ERROR");
        Check(0x400, "CPF_FTP_ERROR");
        Check(0x800, "CPF_HTTP_ERROR");
        Check(0x1000, "CPF_POSTPONED_BASE_LDAP_ERROR");
        Check(0x2000, "CPF_POSTPONED_BASE_FILE_ERROR");

        return string.Join(" | ", names);
    }

    /// <summary>
    /// IEnumCERTVIEWCOLUMN::GetType cannot be reached through <c>dynamic</c>:
    /// the runtime binder resolves GetType to Object.GetType on the runtime
    /// callable wrapper and never asks IDispatch, so the COM method is invoked
    /// by name instead.
    /// </summary>
    private static string DescribeColumnType(object columnEnum)
    {
        try
        {
            var value = columnEnum.GetType().InvokeMember(
                "GetType", BindingFlags.InvokeMethod, null, columnEnum, null);
            return value is int type ? type.ToString() : Describe(value);
        }
        catch (Exception ex)
        {
            return $"(GetType failed: {ex.GetType().Name})";
        }
    }

    private static void ReportSchema(dynamic view)
    {
        object? columnEnumObject = null;
        try
        {
            columnEnumObject = view.EnumCertViewColumn(SchemaColumn);
            dynamic columns = columnEnumObject!;
            Console.WriteLine("    Schema columns:");
            while ((int)columns.Next() != -1)
            {
                string name = (string)columns.GetName();
                string displayName = (string)columns.GetDisplayName();
                Console.WriteLine($"      {name,-24} type={DescribeColumnType(columnEnumObject)} \"{displayName}\"");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"    Schema enumeration failed: {ex.GetType().Name} 0x{Marshal.GetHRForException(ex):X8} {ex.Message}");
        }
        finally
        {
            if (columnEnumObject != null && Marshal.IsComObject(columnEnumObject))
                Marshal.FinalReleaseComObject(columnEnumObject);
        }
    }

    #endregion
}

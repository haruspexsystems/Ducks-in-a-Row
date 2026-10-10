using System.DirectoryServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using Certus.Adcs.ServiceRights;
using Certus.Core.Crl;
using Certus.Core.ServiceRights;

/// <summary>
/// Issues #440 and #469: what the CA and the directory will let the service's
/// own account do, measured rather than read off an access list or a
/// specification.
///
/// Every call here is a read. The questions it settles, one state of the CA's
/// permissions at a time:
///
///   1. Does the wizard's Test Connection (GetCAProperty 6 and 22 through
///      CertRequest) need a right at all, and which one? [MS-CSRA] lists the
///      request interface's GetCAProperty under Enroll, the right the console
///      calls Request Certificates.
///   2. Does ICertAdmin2::GetMyRoles answer, and does its mask follow the CA's
///      security descriptor as the state changes?
///   3. Does the certificate view the inventory sync reads open, and does it
///      see every row, or only some? A denied view and a filtered view are
///      different failures, so the rows are counted, and (issue #469) read back
///      through the sync's own column set, so a view that returns the rows but
///      withholds their columns is caught too.
///   4. Can the account collect a certificate by request id? RetrievePending is
///      kept for comparison with the #440 run, but the product collects with
///      GetIssuedCertificate and GetCertificate, which is what
///      CollectPermissionMessage describes, so that is read as well (#477).
///   5. Does the product's own directory reader, run as the computer account,
///      read the account's groups and each template's permission list, and
///      what does the product's Enroll test make of them?
///   6. Issue #469: do the CA chain (properties 11 and 13), the CA's own CRLs
///      (11, 20, 17, 18, 30, 31, 41) and the request status read the rights
///      check uses (GetRequestStatusAsync) answer, each in the product's exact
///      call shape?
///   7. Issue #469, for the #470 design: do the same chain and CRL properties
///      answer through the admin interface, which Read alone opened on lab 2019
///      where the request interface needed Request Certificates?
///   8. Issue #469: does the template read the product makes over LDAP answer?
///      Directory permissions govern it, not the CA's, so it is read in every
///      state to show that rather than assert it.
///
/// Questions 5 and 8 only mean something as SYSTEM, which reaches the directory
/// as the computer account. Run as the lab administrator inside a WinRM session
/// the same reads make a second hop and fail silently, so the block refuses to
/// run them there rather than print a wrong answer shaped like a right one.
///
/// Lines start with "RIGHTS" so a lab record can be read, and never take the
/// "QI name -> hr=" shape the ship lab gate parses. A failure carries a class:
/// denied (E_ACCESSDENIED or CERTSRV_E_ENROLL_DENIED, the two shapes a CA
/// refusal takes), unavailable (RPC), or error. A line whose value is a list
/// (the ids and requesters a count saw) carries the list as its whole value,
/// because the names in it can contain spaces.
/// </summary>
internal static class RightsProbe
{
    private static readonly Guid CertRequestClsid = new("98aff3f0-5524-11d0-8812-00a0c903b83c");
    private static readonly Guid CertViewClsid = new("a12d0f7a-1e84-11d1-9bd6-00c04fb683fa");
    private static readonly Guid CertAdminClsid = new("37eabaf0-7fb6-11d0-8817-00a0c903b83c");

    private const int CaNameProperty = 6;
    private const int CaSigCertCountProperty = 11;
    private const int CaSigCertChainProperty = 13;
    private const int BaseCrlProperty = 17;
    private const int DeltaCrlProperty = 18;
    private const int CrlStateProperty = 20;
    private const int DnsNameProperty = 22;
    private const int TemplatesProperty = 29;
    private const int BaseCrlPublishProperty = 30;
    private const int DeltaCrlPublishProperty = 31;
    private const int CdpUrlsProperty = 41;

    private const int PropTypeLong = 1;
    private const int PropTypeBinary = 3;
    private const int PropTypeString = 4;

    /// <summary>CR_OUT_BASE64HEADER, CR_OUT_BASE64 and CR_OUT_CHAIN, as the product passes them.</summary>
    private const int OutBase64Header = 0x0;
    private const int OutBase64 = 0x1;
    private const int OutChain = 0x100;

    /// <summary>CA_DISP_VALID: a key whose CRL is worth reading (AdcsCrlReader skips the rest).</summary>
    private const int CaDispositionValid = 3;

    /// <summary>The product's cap on signing key indexes (AdcsCrlReader.MaxKeyIndexes).</summary>
    private const int MaxKeyIndexes = 16;

    /// <summary>CR_DISP_ISSUED and CR_DISP_ISSUED_OUT_OF_BAND, the two answers GetCertificateAsync collects on.</summary>
    private const int RequestDispositionIssued = 3;
    private const int RequestDispositionIssuedOutOfBand = 4;

    private const int SchemaColumn = 0;
    private const int SeekEqual = 0x1;
    private const int SortNone = 0x0;
    private const int DispositionPending = 9;
    private const int DispositionIssued = 20;
    private const int DispositionRevoked = 21;
    private const int DispositionFailed = 30;
    private const int DispositionDenied = 31;

    /// <summary>CV_OUT_BINARY. Ignored for a long column such as RequestID, as in the product's reader.</summary>
    private const int EncodingBinary = 0x2;

    /// <summary>CV_OUT_BASE64, which the product uses for RawCertificate and nothing else.</summary>
    private const int EncodingBase64 = 0x1;

    /// <summary>A lab CA holds dozens of rows; the cap only stops a mistake on a big one.</summary>
    private const int CountCap = 100_000;

    /// <summary>How many request ids a count line lists before it says it stopped.</summary>
    private const int ListedIdCap = 200;

    /// <summary>
    /// The columns the inventory sync asks for, in the order QueryCertificatesAsync
    /// registers them (src/Certus.Adcs/AdcsClient.cs, the columns array there).
    /// The last two keep their table qualifier, see RequestColumnName.
    /// </summary>
    private static readonly string[] SyncColumns =
    [
        "RequestID", "SerialNumber", "CommonName", "DistinguishedName", "CertificateTemplate",
        "NotBefore", "NotAfter", "Disposition", "DispositionMessage", "StatusCode",
        "RequesterName", "SubmittedWhen", "RevokedWhen", "RevokedReason", "RawCertificate",
        "Request.DistinguishedName", "Request.CommonName"
    ];

    /// <summary>The columns GetRequestStatusAsync asks for.</summary>
    private static readonly string[] StatusColumns = ["RequestID", "Disposition", "DispositionMessage", "StatusCode"];

    /// <summary>The two names AdcsClient.NormalizeColumnName leaves qualified.</summary>
    private static readonly string[] QualifiedKeyColumns = ["Request.CommonName", "Request.DistinguishedName"];

    public static void Run(string caConfig)
    {
        var isSystem = ReportIdentity();
        var requestId = ReadInt("CERTUS_PROBE_REQUEST_ID") ?? 1;
        var collectId = ReadInt("CERTUS_PROBE_COLLECT_ID");

        Console.WriteLine();
        ReportRequestProperty(caConfig, "connect.request.caname", CaNameProperty);
        ReportRequestProperty(caConfig, "connect.request.dnsname", DnsNameProperty);
        ReportAdminProperty(caConfig, "connect.admin.caname", CaNameProperty);
        ReportAdminProperty(caConfig, "connect.admin.dnsname", DnsNameProperty);
        ReportTemplateList(caConfig, "connect.request.templates", CertRequestClsid);
        ReportTemplateList(caConfig, "connect.admin.templates", CertAdminClsid);
        ReportRoles(caConfig);

        Console.WriteLine();
        ReportChain(caConfig, "chain.request", CertRequestClsid);
        ReportChain(caConfig, "chain.admin", CertAdminClsid);
        ReportCrls(caConfig, "crl.request", CertRequestClsid);
        ReportCrls(caConfig, "crl.admin", CertAdminClsid);

        Console.WriteLine();
        ReportView(caConfig, "view.absent", int.MaxValue);
        ReportView(caConfig, "view.present", requestId);
        ReportRequestStatus(caConfig, "status.absent", int.MaxValue);
        ReportRequestStatus(caConfig, "status.present", requestId);
        ReportCount(caConfig, "count.issued", DispositionIssued);
        ReportCount(caConfig, "count.revoked", DispositionRevoked);
        ReportCount(caConfig, "count.pending", DispositionPending);
        ReportCount(caConfig, "count.failed", DispositionFailed);
        ReportCount(caConfig, "count.denied", DispositionDenied);
        ReportSyncCount(caConfig, "count.sync.issued", DispositionIssued);
        ReportSyncCount(caConfig, "count.sync.revoked", DispositionRevoked);

        Console.WriteLine();
        PrincipalReading? principal = null;
        if (isSystem)
        {
            principal = DirectoryRightsReader.ReadServicePrincipal();
            ReportPrincipal(principal);
        }
        else
        {
            Line("principal", "skipped", "reason=not running as SYSTEM, so a directory read would be a silent second hop");
        }

        if (principal?.AccountName is { } account)
            ReportOwnRequests(caConfig, account);
        ReportCollect(caConfig, collectId);
        ReportCollectIssued(caConfig, "collect.issued", collectId,
            "set CERTUS_PROBE_COLLECT_ID to one of the account's own request ids");
        ReportCollectIssued(caConfig, "collect.other", requestId, "");

        Console.WriteLine();
        if (isSystem)
            ReportTemplateAttributes();
        else
            Line("templates.ldap", "skipped", "reason=not running as SYSTEM, so a directory read would be a silent second hop");

        if (principal is { Outcome: ReadingOutcome.Ok, AccountSid: { } sid })
        {
            var sids = TemplateEnrollEvaluator.SidsForNetworkLogon(sid, principal.GroupSids);
            foreach (var template in ReadTemplates())
                ReportTemplate(template, sids);
        }
        else
        {
            Line("templates", "skipped", "reason=no principal to evaluate the permission lists against");
        }
    }

    private static bool ReportIdentity()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var isSystem = identity.IsSystem;
        Line("identity", identity.Name, $"sid={identity.User?.Value} system={isSystem}");
        return isSystem;
    }

    private static void ReportRequestProperty(string caConfig, string key, int propertyId)
    {
        object? raw = null;
        try
        {
            raw = Activator.CreateInstance(Type.GetTypeFromCLSID(CertRequestClsid)!);
            dynamic request = raw!;
            var value = (string)request.GetCAProperty(caConfig, propertyId, 0, PropTypeString, 0);
            Line(key, "ok", $"value={value}");
        }
        catch (Exception ex)
        {
            Fail(key, ex);
        }
        finally
        {
            Release(raw);
        }
    }

    private static void ReportAdminProperty(string caConfig, string key, int propertyId)
    {
        object? raw = null;
        try
        {
            raw = Activator.CreateInstance(Type.GetTypeFromCLSID(CertAdminClsid)!);
            dynamic admin = raw!;
            var value = (string)admin.GetCAProperty(caConfig, propertyId, 0, PropTypeString, 0);
            Line(key, "ok", $"value={value}");
        }
        catch (Exception ex)
        {
            Fail(key, ex);
        }
        finally
        {
            Release(raw);
        }
    }

    /// <summary>
    /// CR_PROP_TEMPLATES, as ReadTemplates reads it: name and OID pairs, one per
    /// line. Only the names are printed, since the raw value spans lines.
    /// </summary>
    private static void ReportTemplateList(string caConfig, string key, Guid clsid)
    {
        object? raw = null;
        try
        {
            raw = Activator.CreateInstance(Type.GetTypeFromCLSID(clsid)!);
            dynamic d = raw!;
            var value = (string)d.GetCAProperty(caConfig, TemplatesProperty, 0, PropTypeString, 0);
            var parts = value.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            var names = new List<string>();
            for (var i = 0; i + 1 < parts.Length; i += 2)
            {
                var name = parts[i].Trim();
                if (name.Length > 0)
                    names.Add(name);
            }
            Line(key, "ok", $"count={names.Count} names={string.Join(",", names)}");
        }
        catch (Exception ex)
        {
            Fail(key, ex);
        }
        finally
        {
            Release(raw);
        }
    }

    private static void ReportRoles(string caConfig)
    {
        try
        {
            // The product's own reader, linked in.
            var mask = CaRoleReader.ReadMyRoles(caConfig);
            Line("roles", "ok", $"mask=0x{mask:X} names={string.Join(",", CaAccessRoles.Describe(mask))}");
        }
        catch (Exception ex)
        {
            Fail("roles", ex);
        }
    }

    /// <summary>
    /// The sequence ReadCaCertificateChain uses: the signing certificate count,
    /// then the PKCS#7 chain of the newest key, base64 encoded. Read through
    /// either coclass, since ICertAdmin2::GetCAProperty takes the same arguments.
    /// </summary>
    private static void ReportChain(string caConfig, string prefix, Guid clsid)
    {
        object? raw = null;
        try
        {
            raw = Activator.CreateInstance(Type.GetTypeFromCLSID(clsid)!);
            var count = ReadLongProperty(raw!, caConfig, $"{prefix}.count", CaSigCertCountProperty, 0);
            if (count is not > 0)
                return;

            var key = $"{prefix}.chain";
            dynamic d = raw!;
            byte[] pkcs7;
            try
            {
                var base64 = (string)d.GetCAProperty(caConfig, CaSigCertChainProperty, count.Value - 1, PropTypeBinary, OutBase64);
                pkcs7 = Convert.FromBase64String(base64);
            }
            catch (Exception ex)
            {
                // Under the chain's own key whether the CA refused or answered
                // with something that is not base64, so a state comparison sees
                // a failed line rather than a missing one.
                Fail(key, ex);
                return;
            }

            var certificates = CrlProbe.TryReadPkcs7(pkcs7, out var certs, out _, out var error)
                ? certs.Count.ToString(System.Globalization.CultureInfo.InvariantCulture)
                : $"unreadable({error})";
            Line(key, "ok", $"index={count.Value - 1} bytes={pkcs7.Length} certs={certificates} sha256={Digest(pkcs7)}");
        }
        catch (Exception ex)
        {
            Fail(prefix, ex);
        }
        finally
        {
            Release(raw);
        }
    }

    /// <summary>
    /// The sequence AdcsCrlReader.Read uses, printed property by property. The
    /// product swallows a refusal on everything after property 11, so a CA that
    /// answers the count and refuses the CRLs reads there as "no CRLs"; here each
    /// refusal is its own line.
    /// </summary>
    private static void ReportCrls(string caConfig, string prefix, Guid clsid)
    {
        object? raw = null;
        try
        {
            raw = Activator.CreateInstance(Type.GetTypeFromCLSID(clsid)!);
            var count = ReadLongProperty(raw!, caConfig, $"{prefix}.count", CaSigCertCountProperty, 0);
            if (count is not > 0)
                return;

            var indexes = Math.Min(count.Value, MaxKeyIndexes);
            for (var index = 0; index < indexes; index++)
            {
                var key = $"{prefix}.k{index}";
                var state = ReadLongProperty(raw!, caConfig, $"{key}.state", CrlStateProperty, index);
                if (state is not null && state != CaDispositionValid)
                {
                    Line($"{key}.crls", "skipped", $"reason=state {state} is not CA_DISP_VALID");
                    continue;
                }

                ReportCrl(raw!, caConfig, $"{key}.base", BaseCrlProperty, BaseCrlPublishProperty, index);
                ReportCrl(raw!, caConfig, $"{key}.delta", DeltaCrlProperty, DeltaCrlPublishProperty, index);
            }

            ReportCdpUrls(raw!, caConfig, $"{prefix}.cdp", indexes - 1);
        }
        catch (Exception ex)
        {
            Fail(prefix, ex);
        }
        finally
        {
            Release(raw);
        }
    }

    /// <summary>
    /// One CRL, as AdcsCrlReader.ReadCrl reads it: binary, base64 encoded, parsed
    /// with the product's header reader, and its publish status read only once
    /// the CRL parsed. The CRL number is printed but is no basis for comparing
    /// two states: a CertSvc restart can publish a new one.
    /// </summary>
    private static void ReportCrl(object com, string caConfig, string key, int crlProperty, int publishProperty, int index)
    {
        dynamic d = com;
        string base64;
        try
        {
            base64 = (string)d.GetCAProperty(caConfig, crlProperty, index, PropTypeBinary, OutBase64);
        }
        catch (Exception ex)
        {
            Fail(key, ex);
            return;
        }

        byte[] der;
        try
        {
            der = Convert.FromBase64String(base64);
        }
        catch (FormatException ex)
        {
            Line(key, "unreadable", $"reason=not base64: {Flatten(ex.Message)}");
            return;
        }

        if (!CrlHeaderReader.TryRead(der, out var header, out var error))
        {
            Line(key, "unparsed", $"bytes={der.Length} error={Flatten(error ?? "")}");
            return;
        }

        Line(key, "ok", $"bytes={der.Length} number={header!.CrlNumberHex} delta={header.IsDelta}");
        ReadLongProperty(com, caConfig, $"{key}.publish", publishProperty, index);
    }

    private static void ReportCdpUrls(object com, string caConfig, string key, int index)
    {
        dynamic d = com;
        try
        {
            var value = (string)d.GetCAProperty(caConfig, CdpUrlsProperty, index, PropTypeString, 0);
            var urls = value.Split(['\n', '\r'], StringSplitOptions.RemoveEmptyEntries)
                .Select(line => line.Trim())
                .Where(line => line.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count();
            Line(key, "ok", $"index={index} urls={urls}");
        }
        catch (Exception ex)
        {
            Fail(key, ex);
        }
    }

    /// <summary>A long property, printed either way, and returned when it answered.</summary>
    private static int? ReadLongProperty(object com, string caConfig, string key, int propertyId, int index)
    {
        dynamic d = com;
        try
        {
            var value = (int)d.GetCAProperty(caConfig, propertyId, index, PropTypeLong, 0);
            Line(key, "ok", $"value={value}");
            return value;
        }
        catch (Exception ex)
        {
            Fail(key, ex);
            return null;
        }
    }

    /// <summary>
    /// The sequence GetRequestStatusAsync uses: one request id, no disposition
    /// restriction, one row read. Only the RequestID column is selected; see
    /// <see cref="ReportRequestStatus"/> for the columns the product reads back.
    /// Kept as it was so a run compares line for line with the #440 record.
    /// </summary>
    private static void ReportView(string caConfig, string key, int requestId)
    {
        object? raw = null;
        object? rows = null;
        try
        {
            raw = Activator.CreateInstance(Type.GetTypeFromCLSID(CertViewClsid)!);
            dynamic view = raw!;
            view.OpenConnection(caConfig);
            int idColumn = (int)view.GetColumnIndex(SchemaColumn, "RequestID");
            view.SetResultColumnCount(1);
            view.SetResultColumn(idColumn);
            view.SetRestriction(idColumn, SeekEqual, SortNone, (object)requestId);
            rows = view.OpenView();
            dynamic e = rows!;
            var found = (int)e.Next() != -1;
            Line(key, "opened", $"requestId={requestId} found={found}");
        }
        catch (Exception ex)
        {
            Fail(key, ex);
        }
        finally
        {
            Release(rows);
            Release(raw);
        }
    }

    /// <summary>
    /// GetRequestStatusAsync in full: the four columns it selects, resolved one by
    /// one with only RequestID and Disposition required, a single RequestID
    /// restriction, and the values read back through the column enumerator under
    /// their normalized names. "found" here means the CA returned the row AND its
    /// columns, which <see cref="ReportView"/> cannot show.
    /// </summary>
    private static void ReportRequestStatus(string caConfig, string key, int requestId)
    {
        object? raw = null;
        object? rows = null;
        object? columns = null;
        try
        {
            raw = Activator.CreateInstance(Type.GetTypeFromCLSID(CertViewClsid)!);
            dynamic view = raw!;
            view.OpenConnection(caConfig);

            var resolved = ResolveColumns(raw!, StatusColumns, out var missing);
            var idIndex = resolved["RequestID"];
            view.SetResultColumnCount(resolved.Count);
            foreach (var index in resolved.Values)
                view.SetResultColumn(index);
            view.SetRestriction(idIndex, SeekEqual, SortNone, (object)requestId);

            rows = view.OpenView();
            dynamic e = rows!;
            if ((int)e.Next() == -1)
            {
                Line(key, "notfound", $"requestId={requestId}");
                return;
            }

            columns = e.EnumCertViewColumn();
            var values = ReadColumnValues(columns!, resolved.Count);
            var disposition = values.GetValueOrDefault("Disposition") is int disp ? disp.ToString(System.Globalization.CultureInfo.InvariantCulture) : "unreadable";
            var statusCode = values.GetValueOrDefault("StatusCode") is int code ? $"0x{code:X8}" : "none";
            var messageLength = values.GetValueOrDefault("DispositionMessage") is string message ? message.Length : -1;
            Line(key, "found",
                $"requestId={requestId} disposition={disposition} statusCode={statusCode} messageLength={messageLength} " +
                $"columns={string.Join(",", values.Keys)} missing={string.Join(",", missing)}");
        }
        catch (Exception ex)
        {
            Fail(key, ex);
        }
        finally
        {
            Release(columns);
            Release(rows);
            Release(raw);
        }
    }

    private static void ReportCount(string caConfig, string key, int disposition)
    {
        object? raw = null;
        object? rows = null;
        try
        {
            raw = Activator.CreateInstance(Type.GetTypeFromCLSID(CertViewClsid)!);
            dynamic view = raw!;
            view.OpenConnection(caConfig);
            int idColumn = (int)view.GetColumnIndex(SchemaColumn, "RequestID");
            int dispositionColumn = (int)view.GetColumnIndex(SchemaColumn, "Disposition");
            view.SetResultColumnCount(1);
            view.SetResultColumn(idColumn);
            view.SetRestriction(dispositionColumn, SeekEqual, SortNone, (object)disposition);
            rows = view.OpenView();
            dynamic e = rows!;
            var counted = 0;
            while (counted < CountCap && (int)e.Next() != -1)
                counted++;
            Line(key, "opened", $"rows={counted}{(counted >= CountCap ? "+" : "")}");
        }
        catch (Exception ex)
        {
            Fail(key, ex);
        }
        finally
        {
            Release(rows);
            Release(raw);
        }
    }

    /// <summary>
    /// One disposition pass of the inventory sync, in its own shape: the sync's
    /// column set, one Disposition restriction, every row read back the way
    /// ReadColumnValues reads it. Prints what MapToCertificateInfo would keep (a
    /// row needs RequestID and Disposition), how many rows came back with a
    /// certificate and a serial, and which ids and requesters it saw. A view
    /// filtered by requester shows up in the requesters; one that withholds a
    /// column shows up as kept or withCertificate falling below rows.
    /// </summary>
    private static void ReportSyncCount(string caConfig, string key, int disposition)
    {
        object? raw = null;
        object? rows = null;
        try
        {
            raw = Activator.CreateInstance(Type.GetTypeFromCLSID(CertViewClsid)!);
            dynamic view = raw!;
            view.OpenConnection(caConfig);

            var resolved = ResolveColumns(raw!, SyncColumns, out var missing);
            view.SetResultColumnCount(resolved.Count);
            foreach (var index in resolved.Values)
                view.SetResultColumn(index);
            view.SetRestriction(resolved["Disposition"], SeekEqual, SortNone, (object)disposition);

            rows = view.OpenView();
            dynamic e = rows!;

            var count = 0;
            var kept = 0;
            var withCertificate = 0;
            var withSerial = 0;
            var ids = new List<int>();
            var requesters = new SortedDictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            while (count < CountCap && (int)e.Next() != -1)
            {
                count++;
                object? columns = null;
                try
                {
                    columns = e.EnumCertViewColumn();
                    var values = ReadColumnValues(columns!, resolved.Count);

                    if (values.GetValueOrDefault("RequestID") is int id)
                    {
                        ids.Add(id);
                        if (values.GetValueOrDefault("Disposition") is int)
                            kept++;
                    }
                    if (values.GetValueOrDefault("RawCertificate") is string certificate && DecodesToBytes(certificate))
                        withCertificate++;
                    if (values.GetValueOrDefault("SerialNumber") is string serial && serial.Length > 0)
                        withSerial++;

                    var requester = values.GetValueOrDefault("RequesterName") as string ?? "(none)";
                    requesters[requester] = requesters.GetValueOrDefault(requester) + 1;
                }
                finally
                {
                    Release(columns);
                }
            }

            ids.Sort();
            Line(key, "opened",
                $"rows={count}{(count >= CountCap ? "+" : "")} kept={kept} withCertificate={withCertificate} " +
                $"withSerial={withSerial} maxId={(ids.Count > 0 ? ids[^1] : 0)} missing={string.Join(",", missing)}");
            Line($"{key}.ids",
                string.Join(",", ids.Take(ListedIdCap)) + (ids.Count > ListedIdCap ? ",..." : ""), "");
            Line($"{key}.requesters",
                string.Join(";", requesters.Select(pair => $"{pair.Key}:{pair.Value}")), "");
        }
        catch (Exception ex)
        {
            Fail(key, ex);
        }
        finally
        {
            Release(rows);
            Release(raw);
        }
    }

    /// <summary>
    /// The account's own requests, so a later state with no view access can
    /// still be asked to collect one of them by id (CERTUS_PROBE_COLLECT_ID).
    /// </summary>
    private static void ReportOwnRequests(string caConfig, string account)
    {
        object? raw = null;
        object? rows = null;
        try
        {
            raw = Activator.CreateInstance(Type.GetTypeFromCLSID(CertViewClsid)!);
            dynamic view = raw!;
            view.OpenConnection(caConfig);
            int idColumn = (int)view.GetColumnIndex(SchemaColumn, "RequestID");
            int requesterColumn = (int)view.GetColumnIndex(SchemaColumn, "RequesterName");
            view.SetResultColumnCount(1);
            view.SetResultColumn(idColumn);
            view.SetRestriction(requesterColumn, SeekEqual, SortNone, (object)account);
            rows = view.OpenView();
            dynamic e = rows!;

            var count = 0;
            var latest = 0;
            while (count < CountCap && (int)e.Next() != -1)
            {
                count++;
                object? columns = null;
                try
                {
                    columns = e.EnumCertViewColumn();
                    dynamic c = columns!;
                    if ((int)c.Next() != -1 && c.GetValue(EncodingBinary) is int id && id > latest)
                        latest = id;
                }
                finally
                {
                    Release(columns);
                }
            }
            Line("own.requests", "opened", $"requester={account} rows={count} latestId={latest}");
        }
        catch (Exception ex)
        {
            Fail("own.requests", ex);
        }
        finally
        {
            Release(rows);
            Release(raw);
        }
    }

    /// <summary>
    /// RetrievePending, as #440 measured it. Not the product's collect call, which
    /// is <see cref="ReportCollectIssued"/>; kept so the two can be compared.
    /// </summary>
    private static void ReportCollect(string caConfig, int? requestId)
    {
        if (requestId is not { } id)
        {
            Line("collect", "skipped", "reason=set CERTUS_PROBE_COLLECT_ID to one of the account's own request ids");
            return;
        }

        object? raw = null;
        try
        {
            raw = Activator.CreateInstance(Type.GetTypeFromCLSID(CertRequestClsid)!);
            dynamic request = raw!;
            var disposition = (int)request.RetrievePending(id, caConfig);
            Line("collect", "ok", $"requestId={id} disposition={disposition}");
        }
        catch (Exception ex)
        {
            Fail("collect", ex);
        }
        finally
        {
            Release(raw);
        }
    }

    /// <summary>
    /// GetCertificateAsync's sequence (issue #477): GetIssuedCertificate by
    /// request id with no serial, then, when the CA says issued, the leaf as PEM
    /// and as DER and the PKCS#7 chain, the chain in its own try as the product
    /// has it. collect.issued asks for one of the account's own requests and
    /// collect.other for one it never submitted, so a CA that applies a
    /// submitter rule shows the two answering differently.
    /// </summary>
    private static void ReportCollectIssued(string caConfig, string key, int? requestId, string unsetReason)
    {
        if (requestId is not { } id)
        {
            Line(key, "skipped", $"reason={unsetReason}");
            return;
        }

        object? raw = null;
        try
        {
            raw = Activator.CreateInstance(Type.GetTypeFromCLSID(CertRequestClsid)!);
            dynamic request = raw!;
            var disposition = (int)request.GetIssuedCertificate(caConfig, id, (string?)null);
            if (disposition != RequestDispositionIssued && disposition != RequestDispositionIssuedOutOfBand)
            {
                Line(key, "ok", $"requestId={id} disposition={disposition} certBytes=0 chain=notread");
                return;
            }

            var pem = (string)request.GetCertificate(OutBase64Header);
            var der = Convert.FromBase64String((string)request.GetCertificate(OutBase64));

            string chain;
            try
            {
                var pkcs7 = (string)request.GetCertificate(OutBase64Header | OutChain);
                chain = $"ok chainChars={pkcs7.Length}";
            }
            catch (Exception ex)
            {
                chain = $"fail class={Classify(Marshal.GetHRForException(ex))} hresult=0x{Marshal.GetHRForException(ex):X8}";
            }

            Line(key, "ok", $"requestId={id} disposition={disposition} certBytes={der.Length} pemChars={pem.Length} chain={chain}");
        }
        catch (Exception ex)
        {
            Fail(key, ex);
        }
        finally
        {
            Release(raw);
        }
    }

    private static void ReportPrincipal(PrincipalReading principal)
    {
        Line("principal", principal.Outcome.ToString(),
            $"joined={principal.DomainJoined} domain={principal.DomainName} account={principal.AccountName} " +
            $"sid={principal.AccountSid} machine={principal.IsMachineIdentity} groups={principal.GroupSids.Count}");
        if (principal.GroupSids.Count > 0)
            Line("principal.groups", string.Join(";", principal.GroupSids), "");
        if (principal.Detail is { } detail)
            Line("principal.detail", detail, "");
    }

    /// <summary>
    /// The template read AdcsTemplateDirectoryLookup.ResolveTemplates makes, copied
    /// rather than linked: the real file takes an ILogger, which this probe does
    /// not carry, and its catch everything handler would hide the very failure
    /// this is here to show. Same container, filter, scope, paging, timeouts and
    /// eleven attributes. An empty answer is printed as "empty", because a silent
    /// second hop answers with nothing rather than an error.
    /// </summary>
    private static void ReportTemplateAttributes()
    {
        try
        {
            using var rootDse = new DirectoryEntry("LDAP://RootDSE");
            var configContext = rootDse.Properties["configurationNamingContext"]?.Value as string;
            if (string.IsNullOrEmpty(configContext))
            {
                Line("templates.ldap", "fail", "class=error reason=configurationNamingContext not available");
                return;
            }

            using var templatesEntry = new DirectoryEntry(
                $"LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,{configContext}");
            using var searcher = new DirectorySearcher(templatesEntry)
            {
                Filter = "(objectClass=pKICertificateTemplate)",
                SearchScope = SearchScope.OneLevel,
                PageSize = 1000,
                ClientTimeout = TimeSpan.FromSeconds(30),
                ServerTimeLimit = TimeSpan.FromSeconds(20),
                ServerPageTimeLimit = TimeSpan.FromSeconds(20)
            };
            foreach (var attribute in new[]
                     {
                         "cn", "displayName", "pKIExtendedKeyUsage", "msPKI-Enrollment-Flag", "msPKI-RA-Signature",
                         "msPKI-Certificate-Name-Flag", "msPKI-Minimal-Key-Size", "msPKI-Template-Schema-Version",
                         "msPKI-Private-Key-Flag", "msPKI-RA-Application-Policies", "pKIDefaultCSPs"
                     })
            {
                searcher.PropertiesToLoad.Add(attribute);
            }

            var wanted = new HashSet<string>(ReadTemplates(), StringComparer.OrdinalIgnoreCase);
            var count = 0;
            var withDisplayName = 0;
            var withEku = 0;
            var withEnrollmentFlag = 0;
            var withSchemaVersion = 0;
            var details = new List<string>();

            using var found = searcher.FindAll();
            foreach (SearchResult result in found)
            {
                var cn = First(result, "cn");
                if (string.IsNullOrWhiteSpace(cn))
                    continue;

                count++;
                var displayName = First(result, "displayName");
                if (!string.IsNullOrWhiteSpace(displayName))
                    withDisplayName++;
                if (result.Properties["pKIExtendedKeyUsage"].Count > 0)
                    withEku++;
                if (result.Properties["msPKI-Enrollment-Flag"].Count > 0)
                    withEnrollmentFlag++;
                if (result.Properties["msPKI-Template-Schema-Version"].Count > 0)
                    withSchemaVersion++;

                if (wanted.Contains(cn))
                {
                    details.Add($"templates.ldap.{cn}=found " +
                        $"schema={First(result, "msPKI-Template-Schema-Version")} " +
                        $"enrollmentFlag={First(result, "msPKI-Enrollment-Flag")} " +
                        $"nameFlag={First(result, "msPKI-Certificate-Name-Flag")} " +
                        $"privateKeyFlag={First(result, "msPKI-Private-Key-Flag")} " +
                        $"raSignature={First(result, "msPKI-RA-Signature")} " +
                        $"minKey={First(result, "msPKI-Minimal-Key-Size")} " +
                        $"eku={string.Join(";", All(result, "pKIExtendedKeyUsage"))} " +
                        $"raPolicies={result.Properties["msPKI-RA-Application-Policies"].Count} " +
                        $"csps={result.Properties["pKIDefaultCSPs"].Count} " +
                        $"displayName=\"{displayName}\"");
                    wanted.Remove(cn);
                }
            }

            Line("templates.ldap", count == 0 ? "empty" : "ok",
                $"count={count} withDisplayName={withDisplayName} withEku={withEku} " +
                $"withEnrollmentFlag={withEnrollmentFlag} withSchemaVersion={withSchemaVersion}");
            foreach (var detail in details)
                Console.WriteLine($"  RIGHTS {detail}");
            foreach (var missing in wanted)
                Line($"templates.ldap.{missing}", "notfound", "");
        }
        catch (Exception ex)
        {
            Fail("templates.ldap", ex);
        }
    }

    private static void ReportTemplate(string template, IReadOnlySet<string> sids)
    {
        var reading = DirectoryRightsReader.ReadTemplateDacl(template);
        if (reading.Outcome != ReadingOutcome.Ok)
        {
            Line($"template.{template}", reading.Outcome.ToString(), $"detail={reading.Detail}");
            return;
        }

        var enroll = TemplateEnrollEvaluator.Evaluate(reading.Entries, sids, TemplateEnrollEvaluator.EnrollRight);
        var autoenroll = TemplateEnrollEvaluator.Evaluate(reading.Entries, sids, TemplateEnrollEvaluator.AutoenrollRight);
        Line($"template.{template}", "Ok",
            $"enroll={enroll.Verdict} decidedBy={enroll.DecidingSid} inherited={enroll.DecidedByInheritedEntry} " +
            $"autoenroll={autoenroll.Verdict} entries={reading.Entries.Count}");
        Line($"template.{template}.sddl", reading.Sddl ?? "", "");
    }

    /// <summary>
    /// GetColumnIndex for each name, as the product resolves its columns: a name
    /// the CA does not know costs that column, except RequestID and Disposition,
    /// whose absence would make every row unreadable and so throws.
    /// </summary>
    private static Dictionary<string, int> ResolveColumns(object viewObject, string[] names, out List<string> missing)
    {
        dynamic view = viewObject;
        var resolved = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        missing = [];
        foreach (var name in names)
        {
            try
            {
                resolved[name] = (int)view.GetColumnIndex(SchemaColumn, name);
            }
            catch (Exception) when (name is not ("RequestID" or "Disposition"))
            {
                missing.Add(name);
            }
        }
        return resolved;
    }

    /// <summary>
    /// The product's ReadColumnValues: names normalized as NormalizeColumnName
    /// does, RawCertificate read as base64 and everything else as binary, a
    /// column that will not read recorded as null, and the first value kept when
    /// two names collide.
    /// </summary>
    private static Dictionary<string, object?> ReadColumnValues(object columnEnum, int count)
    {
        dynamic c = columnEnum;
        var values = new Dictionary<string, object?>(StringComparer.Ordinal);
        for (var i = 0; i < count; i++)
        {
            if ((int)c.Next() == -1)
                break;

            var name = NormalizeColumnName((string)c.GetName());
            var encoding = string.Equals(name, "RawCertificate", StringComparison.OrdinalIgnoreCase)
                ? EncodingBase64
                : EncodingBinary;

            object? value;
            try
            {
                value = (object?)c.GetValue(encoding);
            }
            catch (COMException)
            {
                value = null;
            }
            values.TryAdd(name, value);
        }
        return values;
    }

    /// <summary>AdcsClient.NormalizeColumnName, which this must match.</summary>
    private static string NormalizeColumnName(string name)
    {
        foreach (var qualified in QualifiedKeyColumns)
        {
            if (string.Equals(qualified, name, StringComparison.OrdinalIgnoreCase))
                return qualified;
        }

        var lastDot = name.LastIndexOf('.');
        return lastDot >= 0 && lastDot < name.Length - 1 ? name[(lastDot + 1)..] : name;
    }

    private static bool DecodesToBytes(string base64)
    {
        try
        {
            return Convert.FromBase64String(base64).Length > 0;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static string Digest(byte[] bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes))[..16].ToLowerInvariant();

    private static string First(SearchResult result, string property)
    {
        var values = result.Properties[property];
        return values.Count > 0 ? Convert.ToString(values[0], System.Globalization.CultureInfo.InvariantCulture) ?? "" : "";
    }

    private static IEnumerable<string> All(SearchResult result, string property)
    {
        foreach (var value in result.Properties[property])
            yield return Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture) ?? "";
    }

    private static IEnumerable<string> ReadTemplates()
    {
        var raw = Environment.GetEnvironmentVariable("CERTUS_PROBE_TEMPLATE");
        if (string.IsNullOrWhiteSpace(raw))
            return [];
        return raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    private static int? ReadInt(string variable)
        => int.TryParse(Environment.GetEnvironmentVariable(variable), out var value) ? value : null;

    private static void Line(string key, string value, string rest)
    {
        Console.WriteLine(rest.Length == 0 ? $"  RIGHTS {key}={value}" : $"  RIGHTS {key}={value} {rest}");
    }

    private static void Fail(string key, Exception ex)
    {
        var hresult = Marshal.GetHRForException(ex);
        Line(key, "fail",
            $"class={Classify(hresult)} type={ex.GetType().Name} hresult=0x{hresult:X8} message={Flatten(ex.Message)}");
    }

    /// <summary>
    /// A CA refuses in one of two shapes: E_ACCESSDENIED, or CERTSRV_E_ENROLL_DENIED
    /// on the request interface (measured on lab 2019 for #440). Both are a
    /// refusal, the rule CaAccessDeniedException.IsRefusal applies. RPC_S_SERVER_UNAVAILABLE
    /// and RPC_S_CALL_FAILED are an outage, not an answer about rights.
    /// </summary>
    private static string Classify(int hresult) => unchecked((uint)hresult) switch
    {
        0x80070005 or 0x80094011 => "denied",
        0x800706BA or 0x800706BE => "unavailable",
        _ => "error"
    };

    private static string Flatten(string text) => text.ReplaceLineEndings(" ").Trim();

    private static void Release(object? comObject)
    {
        if (comObject != null && Marshal.IsComObject(comObject))
            Marshal.FinalReleaseComObject(comObject);
    }
}

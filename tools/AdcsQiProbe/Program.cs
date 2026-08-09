using System.Diagnostics;
using System.Runtime.InteropServices;

// Diagnostic for Certus issue #14.
//
// First round result on .19: STA and MTA both returned E_NOINTERFACE for
// ICertRequest2 and ICertView2 IIDs, even though `certutil -ping` succeeds
// against the same CA from the same host. This second round widens the probe to
// distinguish three remaining hypotheses (see plan):
//
//   1. The coclass exposes v1 but not v2 (registry/version mismatch).
//   2. .NET's Activator.CreateInstance(Type.GetTypeFromCLSID(...)) path is going
//      through a stale managed wrapper rather than CoCreateInstance.
//   3. The wrong certcli.dll is being loaded into the .NET process.
//
// To distinguish:
//   * QI for IUnknown, IDispatch, ICertRequest (v1), ICertRequest2, ICertRequest3
//     -> tells us which interfaces the object actually claims.
//   * Activator path + raw P/Invoke CoCreateInstance path side by side
//     -> tells us if the managed wrapping is the cause.
//   * Print the loaded certcli.dll path/version
//     -> tells us which native binary is bound into the process.

Console.WriteLine("Certus AdcsQiProbe — issue #14 widened diagnostic");
Console.WriteLine($"Process: PID={Environment.ProcessId}, User={Environment.UserDomainName}\\{Environment.UserName}, Bitness={(IntPtr.Size == 8 ? "x64" : "x86")}");
Console.WriteLine();

// Force certcli.dll to load so we can report its module path before activation.
// A load failure is itself informative, so report it with the Win32 error.
if (NativeMethods.LoadLibraryW("certcli.dll") == IntPtr.Zero)
    Console.WriteLine($"  certcli.dll failed to load (Win32 error {Marshal.GetLastWin32Error()}).");
if (NativeMethods.LoadLibraryW("certadm.dll") == IntPtr.Zero)
    Console.WriteLine($"  certadm.dll failed to load (Win32 error {Marshal.GetLastWin32Error()}).");

PrintLoadedModules();
Console.WriteLine();

// IIDs we care about.
var iids = new (string Name, Guid Iid)[]
{
    ("IUnknown",       new Guid("00000000-0000-0000-c000-000000000046")),
    ("IDispatch",      new Guid("00020400-0000-0000-c000-000000000046")),
    ("ICertRequest",   new Guid("014e4840-5523-11d0-8812-00a0c903b83c")), // v1
    ("ICertRequest2",  new Guid("728ab34f-217d-11da-b2a4-000e7bbb2b09")), // v2
    ("ICertRequest3",  new Guid("11916a73-3a35-4bf2-9c80-7a4f30b97e2d")), // v3 (Server 2012+)
};

var viewIids = new (string Name, Guid Iid)[]
{
    ("IUnknown",   new Guid("00000000-0000-0000-c000-000000000046")),
    ("IDispatch",  new Guid("00020400-0000-0000-c000-000000000046")),
    ("ICertView",  new Guid("c3fac344-1e84-11d1-9bd6-00c04fb683fa")), // v1
    ("ICertView2", new Guid("d594b282-8851-4b61-9c66-3edadf848863")), // v2 — IID corrected from earlier 848864 typo (issue #15)
};

// Issue #169: revocation (PR #202) dispatches through CertAdminClass, so the
// net10 upgrade gate needs its activation and QI facts too. QI only, never a
// method call: every CertAdmin method mutates a live CA (RevokeCertificate
// and friends), so unlike the CertView invocation probe there is no safe
// method to exercise. IIDs from certadm.h.
var adminIids = new (string Name, Guid Iid)[]
{
    ("IUnknown",    new Guid("00000000-0000-0000-c000-000000000046")),
    ("IDispatch",   new Guid("00020400-0000-0000-c000-000000000046")),
    ("ICertAdmin",  new Guid("34df6950-7fb6-11d0-8817-00a0c903b83c")), // v1
    ("ICertAdmin2", new Guid("f7c3ac41-b8ce-4fb4-aa58-3d1dc0e36b39")), // v2
};

RunCoclass("CertRequestClass", new Guid("98aff3f0-5524-11d0-8812-00a0c903b83c"), iids);
Console.WriteLine();
RunCoclass("CertViewClass",    new Guid("a12d0f7a-1e84-11d1-9bd6-00c04fb683fa"), viewIids);
Console.WriteLine();
RunCoclass("CertAdminClass",   new Guid("37eabaf0-7fb6-11d0-8817-00a0c903b83c"), adminIids);

// Issue #15: QI for v1 IIDs already known to succeed. The remaining open question is
// which managed dispatch model actually executes a v1 method without the
// AccessViolationException seen at SetResultColumnCount in commit 66973a7. We probe
// by invoking OpenConnection + SetResultColumnCount(0) on a CertViewClass through
// each candidate model and reporting the outcome.
Console.WriteLine();
Console.WriteLine("=== Method invocation probe (issue #15) ===");

string? caConfig = Environment.GetEnvironmentVariable("CERTUS_PROBE_CA");
if (string.IsNullOrWhiteSpace(caConfig))
{
    Console.WriteLine("  Skipped: set CERTUS_PROBE_CA=\"<host>\\<CA name>\" to enable.");
}
else
{
    Console.WriteLine($"  CA config: {caConfig}");
    InvokeProbe.RunAll(caConfig);
}

// Dashboard sync mapping probe: prints what GetName() and GetValue() actually
// return for the exact result column set the certificate sync requests. See the
// block comment on ColumnProbe below.
Console.WriteLine();
Console.WriteLine("=== Column name probe (dashboard sync mapping) ===");
if (string.IsNullOrWhiteSpace(caConfig))
{
    Console.WriteLine("  Skipped: set CERTUS_PROBE_CA=\"<host>\\<CA name>\" to enable.");
}
else
{
    Console.WriteLine($"  CA config: {caConfig}");
    ColumnProbe.Run(caConfig);
}

static void RunCoclass(string label, Guid clsid, (string Name, Guid Iid)[] iids)
{
    Console.WriteLine($"=== {label} ({clsid}) ===");

    var t = Type.GetTypeFromCLSID(clsid, throwOnError: false);
    Console.WriteLine($"  Type.GetTypeFromCLSID -> {(t is null ? "null" : t.AssemblyQualifiedName)}");

    // Path A: Activator.CreateInstance (matches what `new CoclassClass()` does in [ComImport]).
    Console.WriteLine("  Path A: Activator.CreateInstance(Type.GetTypeFromCLSID)");
    if (t is not null)
    {
        try
        {
            var raw = Activator.CreateInstance(t);
            if (raw is null)
            {
                Console.WriteLine("    activate -> null");
            }
            else
            {
                try
                {
                    IntPtr unk = Marshal.GetIUnknownForObject(raw);
                    try { QiAll(unk, iids, "    "); }
                    finally { Marshal.Release(unk); }
                }
                finally
                {
                    if (Marshal.IsComObject(raw)) Marshal.FinalReleaseComObject(raw);
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"    activate -> {ex.GetType().Name}: 0x{Marshal.GetHRForException(ex):X8} {ex.Message}");
        }
    }

    // Path B: raw P/Invoke CoCreateInstance, bypasses .NET RCW machinery entirely.
    Console.WriteLine("  Path B: P/Invoke CoCreateInstance(CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER, IID_IUnknown)");
    var iidUnknown = iids[0].Iid;
    int hr = NativeMethods.CoCreateInstance(ref clsid, IntPtr.Zero, NativeMethods.CLSCTX.INPROC_SERVER | NativeMethods.CLSCTX.LOCAL_SERVER, ref iidUnknown, out IntPtr ppv);
    if (hr != 0)
    {
        Console.WriteLine($"    CoCreateInstance -> hr=0x{hr:X8} ({Decode(hr)})");
    }
    else
    {
        try { QiAll(ppv, iids, "    "); }
        finally { Marshal.Release(ppv); }
    }
}

static void QiAll(IntPtr unk, (string Name, Guid Iid)[] iids, string indent)
{
    foreach (var (name, iid) in iids)
    {
        var iidLocal = iid;
        // Marshal.QueryInterface changed its iid parameter from ref to in
        // between net8 and net10, and this file builds for both targets
        // during the issue #169 gate, so each target calls with its own
        // modifier.
#if NET10_0_OR_GREATER
        int hr = Marshal.QueryInterface(unk, in iidLocal, out IntPtr p);
#else
        int hr = Marshal.QueryInterface(unk, ref iidLocal, out IntPtr p);
#endif
        if (p != IntPtr.Zero) Marshal.Release(p);
        Console.WriteLine($"{indent}QI {name,-15} -> hr=0x{hr:X8} ({Decode(hr)})  iface={(p != IntPtr.Zero ? "non-null" : "null")}");
    }
}

static void PrintLoadedModules()
{
    Console.WriteLine("Loaded native modules of interest:");
    var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    foreach (ProcessModule m in Process.GetCurrentProcess().Modules)
    {
        var name = m.ModuleName;
        if (name is null) continue;
        if (!name.StartsWith("certcli", StringComparison.OrdinalIgnoreCase) &&
            !name.StartsWith("certadm", StringComparison.OrdinalIgnoreCase) &&
            !name.StartsWith("rpcrt4",  StringComparison.OrdinalIgnoreCase) &&
            !name.StartsWith("ole32",   StringComparison.OrdinalIgnoreCase) &&
            !name.StartsWith("combase", StringComparison.OrdinalIgnoreCase))
            continue;
        if (!seen.Add(name)) continue;
        Console.WriteLine($"  {name,-16} {m.FileName,-60} v{m.FileVersionInfo.FileVersion}");
    }
}

static string Decode(int hr) => (uint)hr switch
{
    0x00000000 => "S_OK",
    0x80004002 => "E_NOINTERFACE",
    0x80040154 => "REGDB_E_CLASSNOTREG",
    0x80004005 => "E_FAIL",
    0x80040111 => "CLASS_E_CLASSNOTAVAILABLE",
    0x800401F0 => "CO_E_NOTINITIALIZED",
    _          => "other",
};

// Issue #15: a test of how managed code can invoke v1 methods on CCertView,
// trying each candidate dispatch model in turn. SetResultColumnCount(0) is the
// cheapest real method call after OpenConnection and is harmless on the CA
// database.
//
// Isolation between models is partial, not absolute. The try/catch in TryModel
// only catches managed exceptions. It catches the NullReferenceException that
// the broken InterfaceIsIUnknown model produces here, because argument 0 maps to
// the null page and the CLR surfaces that as a managed exception. It would not
// catch a true AccessViolationException from a bad pointer that is not the null
// page (the production crash was SetResultColumnCount(10), where 10 is
// dereferenced as a pointer); on net8 that is a corrupted state exception that
// terminates the process. To keep a hard crash from hiding the results that
// matter, the three sound models run first and stdout is flushed before each
// call, so the transcript always shows which model was in flight.
internal static class InvokeProbe
{
    public static void RunAll(string caConfig)
    {
        TryModel("dynamic / IDispatch via runtime binder", () =>
        {
            object? raw = null;
            try
            {
                raw = Activator.CreateInstance(Type.GetTypeFromCLSID(CertViewClsid)!);
                dynamic view = raw!;
                view.OpenConnection(caConfig);
                view.SetResultColumnCount(0);
            }
            finally { ReleaseRcw(raw); }
        });

        TryModel("InterfaceIsIDispatch (typed, named lookup)", () =>
        {
            object? raw = null;
            try
            {
                raw = Activator.CreateInstance(Type.GetTypeFromCLSID(CertViewClsid)!);
                var view = (ICertViewIDispatch)raw!;
                view.OpenConnection(caConfig);
                view.SetResultColumnCount(0);
            }
            finally { ReleaseRcw(raw); }
        });

        TryModel("InterfaceIsDual", () =>
        {
            object? raw = null;
            try
            {
                raw = Activator.CreateInstance(Type.GetTypeFromCLSID(CertViewClsid)!);
                var view = (ICertViewDual)raw!;
                view.OpenConnection(caConfig);
                view.SetResultColumnCount(0);
            }
            finally { ReleaseRcw(raw); }
        });

        // Run the broken model last: if a hard access violation ever replaced the
        // caught NullReferenceException here, the three sound results above would
        // still have printed.
        TryModel("InterfaceIsIUnknown (current 66973a7)", () =>
        {
            object? raw = null;
            try
            {
                raw = Activator.CreateInstance(Type.GetTypeFromCLSID(CertViewClsid)!);
                var view = (ICertViewIUnknown)raw!;
                view.OpenConnection(caConfig);
                view.SetResultColumnCount(0);
            }
            finally { ReleaseRcw(raw); }
        });
    }

    static readonly Guid CertViewClsid = new("a12d0f7a-1e84-11d1-9bd6-00c04fb683fa");

    static void TryModel(string label, Action act)
    {
        Console.Write($"  {label}: ");
        Console.Out.Flush();
        try
        {
            act();
            Console.WriteLine("OK — OpenConnection + SetResultColumnCount(0) succeeded.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"FAIL — {ex.GetType().Name}: 0x{Marshal.GetHRForException(ex):X8} {ex.Message}");
        }
    }

    static void ReleaseRcw(object? o)
    {
        if (o != null && Marshal.IsComObject(o))
            Marshal.FinalReleaseComObject(o);
    }

    [ComImport]
    [Guid("c3fac344-1e84-11d1-9bd6-00c04fb683fa")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface ICertViewIUnknown
    {
        void OpenConnection([MarshalAs(UnmanagedType.BStr)] string strConfig);
        [return: MarshalAs(UnmanagedType.Interface)] object EnumCertViewColumn(int fResultColumn);
        int GetColumnCount(int fResultColumn);
        int GetColumnIndex(int fResultColumn, [MarshalAs(UnmanagedType.BStr)] string strColumnName);
        void SetResultColumnCount(int cResultColumn);
    }

    [ComImport]
    [Guid("c3fac344-1e84-11d1-9bd6-00c04fb683fa")]
    [InterfaceType(ComInterfaceType.InterfaceIsDual)]
    interface ICertViewDual
    {
        void OpenConnection([MarshalAs(UnmanagedType.BStr)] string strConfig);
        [return: MarshalAs(UnmanagedType.Interface)] object EnumCertViewColumn(int fResultColumn);
        int GetColumnCount(int fResultColumn);
        int GetColumnIndex(int fResultColumn, [MarshalAs(UnmanagedType.BStr)] string strColumnName);
        void SetResultColumnCount(int cResultColumn);
    }

    [ComImport]
    [Guid("c3fac344-1e84-11d1-9bd6-00c04fb683fa")]
    [InterfaceType(ComInterfaceType.InterfaceIsIDispatch)]
    interface ICertViewIDispatch
    {
        void OpenConnection([MarshalAs(UnmanagedType.BStr)] string strConfig);
        [return: MarshalAs(UnmanagedType.Interface)] object EnumCertViewColumn(int fResultColumn);
        int GetColumnCount(int fResultColumn);
        int GetColumnIndex(int fResultColumn, [MarshalAs(UnmanagedType.BStr)] string strColumnName);
        void SetResultColumnCount(int cResultColumn);
    }
}

// Dashboard sync mapping probe. The certificate sync in AdcsClient keys row
// values by IEnumCERTVIEWCOLUMN::GetName() and reads them back by unqualified
// ColumnName constants. The hypothesis behind the all Failed dashboard rows is
// that GetName() returns the canonical, table qualified schema name (for
// example "Request.Disposition") for request table columns, while
// GetColumnIndex accepts the unqualified form when building the query. This
// block requests the exact column set the sync uses (plus RawCertificate),
// reads row 1 of the issued disposition, and prints for each result column the
// name GetName() returns and the CLR type GetValue() produces through the
// dynamic IDispatch path. Types and lengths only; no cell values are printed,
// with one deliberate exception: StatusCode is an HRESULT rather than row data
// and its numeric value is the thing being probed.
// For RawCertificate it additionally reports whether GetValue(Base64) yields a
// decodable base64 string, which is what the sync will rely on for SAN
// extraction.
//
// Issue #151 added three more passes over the request dispositions. It surfaces
// DispositionMessage and StatusCode, which only carry information on pending,
// denied, and failed rows, and it needs a Disposition equality restriction and a
// SubmittedWhen GreaterOrEqual restriction to apply together to bound how far
// back the sync reaches. Neither column has ever been requested from a real CA,
// and no shipped code path has ever combined two restrictions with mixed
// operators, so both are probed here before the managed side depends on them.
internal static class ColumnProbe
{
    static readonly Guid CertViewClsid = new("a12d0f7a-1e84-11d1-9bd6-00c04fb683fa");

    // Mirrors the ColumnName constants in src/Certus.Adcs, which this tool
    // deliberately does not reference.
    static readonly string[] Columns =
    [
        "RequestID",
        "SerialNumber",
        "CommonName",
        "DistinguishedName",
        "CertificateTemplate",
        "NotBefore",
        "NotAfter",
        "Disposition",
        "RequesterName",
        "SubmittedWhen",
        "RevokedWhen",
        "RevokedReason",
        "DispositionMessage",
        "StatusCode",
        "RawCertificate",
        // The CA schema carries the request subject separately from the issued
        // one: "CommonName" is the issued certificate's name and is empty until
        // issuance, so a pending or denied row has no name at all today. These
        // two should hold the name from the CSR. Both are probed qualified,
        // because the question is not only whether they resolve but what
        // GetName() hands back: if it returns the qualified form, then after
        // AdcsClient.NormalizeColumnName strips the table they collide with the
        // issued columns, and ReadColumnValues uses TryAdd, so whichever the CA
        // enumerates first silently wins. That collision has to be resolved
        // before either can be read.
        "Request.CommonName",
        "Request.DistinguishedName",
        // Bounds the denied and failed passes by when the CA decided rather than
        // when the request arrived. A request submitted before the window but
        // denied inside it is invisible to a SubmittedWhen bound.
        "ResolvedWhen",
    ];

    const int SchemaColumn = 0;          // ColumnType.Schema
    const int SeekEqual = 0x1;           // SeekOperator.Equal
    const int SeekGreaterOrEqual = 0x8;  // SeekOperator.GreaterOrEqual
    const int SortNone = 0x0;            // SortOrder.None
    const int DbDispositionActive = 8;   // DbDisposition.Active
    const int DbDispositionPending = 9;  // DbDisposition.Pending
    const int DbDispositionIssued = 20;  // DbDisposition.Issued
    const int DbDispositionError = 30;   // DbDisposition.Error
    const int DbDispositionDenied = 31;  // DbDisposition.Denied
    const int EncodingBase64 = 0x1;      // OutputEncoding.Base64
    const int EncodingBinary = 0x2;      // OutputEncoding.Binary

    // Upper bound on the per pass row count. A denied or failed disposition can
    // hold a very large number of rows, and this tool must not enumerate a
    // production CA's whole request table to answer a schema question.
    const int RowCountCap = 500;

    public static void Run(string caConfig)
    {
        // Pass 1 is the sync's existing hot path: it confirms the GetName()
        // qualification hypothesis and the RawCertificate encoding.
        RunPass(caConfig, "Disposition=20 (Issued)", view =>
        {
            int dispIdx = (int)view.GetColumnIndex(SchemaColumn, "Disposition");
            view.SetRestriction(dispIdx, SeekEqual, SortNone, DbDispositionIssued);
        });

        // Passes 2 and 3 cover the request dispositions issue #151 adds. These
        // are the only rows where DispositionMessage and StatusCode carry
        // anything, so this is where their CLR types are actually observable.
        // On an issued row the CA hands back sentinel values instead.
        RunPass(caConfig, "Disposition=9 (Pending)", view =>
        {
            int dispIdx = (int)view.GetColumnIndex(SchemaColumn, "Disposition");
            view.SetRestriction(dispIdx, SeekEqual, SortNone, DbDispositionPending);
        });

        RunPass(caConfig, "Disposition=31 (Denied)", view =>
        {
            int dispIdx = (int)view.GetColumnIndex(SchemaColumn, "Disposition");
            view.SetRestriction(dispIdx, SeekEqual, SortNone, DbDispositionDenied);
        });

        // Disambiguates 8 (Active) from 9 (Pending). The sync's pending pass
        // restricts on 9, which is what the certsrv "Pending Requests" folder
        // shows, but 8 is the other value a request awaiting a decision can
        // carry. If a request is sitting pending on the lab CA and pass 2 comes
        // back empty while this one returns it, the sync has to restrict on 8.
        RunPass(caConfig, "Disposition=8 (Active), to disambiguate against 9", view =>
        {
            int dispIdx = (int)view.GetColumnIndex(SchemaColumn, "Disposition");
            view.SetRestriction(dispIdx, SeekEqual, SortNone, DbDispositionActive);
        });

        // Pass 4 is the unproven one. The time bounded sync needs an equality
        // restriction on Disposition and a GreaterOrEqual restriction on
        // SubmittedWhen to apply together. AdcsClient already assumes a mixed
        // operator pair works (Disposition plus NotAfter), but nothing in the
        // product ever sets ExpiringBefore, so that combination has probably
        // never run against a real CA. If this pass fails, the window has to
        // move to a client side filter instead.
        RunPass(caConfig, "Disposition=9 AND SubmittedWhen>=now-30d", view =>
        {
            int dispIdx = (int)view.GetColumnIndex(SchemaColumn, "Disposition");
            view.SetRestriction(dispIdx, SeekEqual, SortNone, DbDispositionPending);

            int submittedIdx = (int)view.GetColumnIndex(SchemaColumn, "SubmittedWhen");
            object cutoff = DateTime.UtcNow.AddDays(-30);
            view.SetRestriction(submittedIdx, SeekGreaterOrEqual, SortNone, cutoff);
        });

        // Passes for issue #187. The sync bounds its denied and failed passes
        // by SubmittedWhen, which misses a request submitted before the window
        // but decided inside it; ResolvedWhen is when the CA decided, so it is
        // the bound those passes actually want. Two questions have never been
        // answered on a real CA: does a Disposition equality plus a
        // ResolvedWhen GreaterOrEqual apply together, and is ResolvedWhen
        // populated on decided rows at all. The registered result columns
        // above print its name, CLR type, and row 1 value either way, which
        // answers the second question even if the restriction fails.
        RunPass(caConfig, "Disposition=31 AND ResolvedWhen>=now-30d", view =>
        {
            int dispIdx = (int)view.GetColumnIndex(SchemaColumn, "Disposition");
            view.SetRestriction(dispIdx, SeekEqual, SortNone, DbDispositionDenied);

            int resolvedIdx = (int)view.GetColumnIndex(SchemaColumn, "ResolvedWhen");
            object cutoff = DateTime.UtcNow.AddDays(-30);
            view.SetRestriction(resolvedIdx, SeekGreaterOrEqual, SortNone, cutoff);
        });

        // The failed disposition has never been probed on its own: the sync's
        // Failed pass restricts on 30, and nothing so far proves the lab CA
        // returns rows for it. An empty result here proves nothing either way
        // (the lab may simply hold no failed requests); the pass exists to
        // catch a refused restriction and to print the row shape when a
        // failed request does exist.
        RunPass(caConfig, "Disposition=30 (Error/Failed)", view =>
        {
            int dispIdx = (int)view.GetColumnIndex(SchemaColumn, "Disposition");
            view.SetRestriction(dispIdx, SeekEqual, SortNone, DbDispositionError);
        });

        RunPass(caConfig, "Disposition=30 AND ResolvedWhen>=now-30d", view =>
        {
            int dispIdx = (int)view.GetColumnIndex(SchemaColumn, "Disposition");
            view.SetRestriction(dispIdx, SeekEqual, SortNone, DbDispositionError);

            int resolvedIdx = (int)view.GetColumnIndex(SchemaColumn, "ResolvedWhen");
            object cutoff = DateTime.UtcNow.AddDays(-30);
            view.SetRestriction(resolvedIdx, SeekGreaterOrEqual, SortNone, cutoff);
        });

        // The product shape. AdcsClient restricts on ResolvedWhen without
        // registering it as a result column, while every pass above selects
        // it, and restricting on an unselected column is a configuration
        // nothing had exercised. This codebase has been burned by exactly this
        // kind of narrow difference before, so the pass exists rather than the
        // assumption.
        RunPass(caConfig, "Disposition=31 AND ResolvedWhen>=now-30d (restrict only, not a result column)", view =>
        {
            int dispIdx = (int)view.GetColumnIndex(SchemaColumn, "Disposition");
            view.SetRestriction(dispIdx, SeekEqual, SortNone, DbDispositionDenied);

            int resolvedIdx = (int)view.GetColumnIndex(SchemaColumn, "ResolvedWhen");
            object cutoff = DateTime.UtcNow.AddDays(-30);
            view.SetRestriction(resolvedIdx, SeekGreaterOrEqual, SortNone, cutoff);
        }, resultColumns: Columns.Where(c => c != "ResolvedWhen").ToArray());
    }

    /// <summary>
    /// Opens a fresh CertView, registers the result column set, applies the
    /// caller's restriction, and reports the row count plus the column shape of
    /// row 1. Each pass gets its own coclass because restrictions accumulate on
    /// a view and OpenView consumes it.
    /// </summary>
    static void RunPass(string caConfig, string label, Action<dynamic> restrict, string[]? resultColumns = null)
    {
        Console.WriteLine();
        Console.WriteLine($"  --- Pass: {label} ---");

        object? raw = null;
        object? rowEnum = null;
        try
        {
            raw = Activator.CreateInstance(Type.GetTypeFromCLSID(CertViewClsid)!);
            dynamic view = raw!;
            view.OpenConnection(caConfig);

            // Resolve every column first and register only what resolved, so one
            // unrecognised schema name reports itself instead of killing the
            // pass. This mirrors the guard AdcsClient uses for the same reason.
            // A pass may narrow the result column set to test a restriction on
            // a column that is not selected, which is how the product client
            // uses ResolvedWhen.
            var columns = resultColumns ?? Columns;
            var resolved = new List<int>(columns.Length);
            foreach (var col in columns)
            {
                try
                {
                    int idx = (int)view.GetColumnIndex(SchemaColumn, col);
                    resolved.Add(idx);
                    Console.WriteLine($"    GetColumnIndex(Schema, \"{col}\") -> {idx}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"    GetColumnIndex(Schema, \"{col}\") -> FAILED {ex.GetType().Name} 0x{Marshal.GetHRForException(ex):X8}");
                }
            }

            view.SetResultColumnCount(resolved.Count);
            foreach (var idx in resolved)
                view.SetResultColumn(idx);

            try
            {
                restrict(view);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"    SetRestriction failed: {ex.GetType().Name} 0x{Marshal.GetHRForException(ex):X8} {ex.Message}");
                Console.WriteLine("    (this pass proves the restriction is NOT usable; continuing to the next pass)");
                return;
            }

            rowEnum = view.OpenView();
            dynamic e = rowEnum!;
            if ((int)e.Next() == -1)
            {
                Console.WriteLine("    View returned no rows. If this is a request disposition, submit or deny a");
                Console.WriteLine("    request on the lab CA and re-run; an empty pass proves nothing either way.");
                return;
            }

            object? colEnumObj = null;
            try
            {
                colEnumObj = e.EnumCertViewColumn();
                dynamic colEnum = colEnumObj!;
                Console.WriteLine($"    Row 1 result columns ({resolved.Count} registered):");
                while ((int)colEnum.Next() != -1)
                {
                    string name = (string)colEnum.GetName();
                    // StatusCode is an HRESULT, not row data, and its value is
                    // the point of probing it: a signed int here means the
                    // managed side must format it unsigned to be readable.
                    bool isStatusCode = name.EndsWith("StatusCode", StringComparison.OrdinalIgnoreCase);
                    string binaryReport = DescribeGetValue(colEnum, EncodingBinary, showIntValue: isStatusCode);
                    Console.WriteLine($"      GetName=\"{name}\"  GetValue(Binary) -> {binaryReport}");
                    if (name.EndsWith("RawCertificate", StringComparison.OrdinalIgnoreCase))
                    {
                        string base64Report = DescribeGetValue(colEnum, EncodingBase64, checkBase64: true);
                        Console.WriteLine($"        GetValue(Base64) -> {base64Report}");
                    }
                }
            }
            finally
            {
                if (colEnumObj != null && Marshal.IsComObject(colEnumObj))
                    Marshal.FinalReleaseComObject(colEnumObj);
            }

            // Row count, bounded. A denied or failed disposition can hold a very
            // large number of rows on a busy CA, which is the cost the time
            // bounded sync exists to contain, so the number matters here.
            var counted = 1;
            while (counted < RowCountCap && (int)e.Next() != -1)
                counted++;
            Console.WriteLine(counted >= RowCountCap
                ? $"    Rows in this pass: {RowCountCap}+ (stopped counting at the cap)"
                : $"    Rows in this pass: {counted}");
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

    static string DescribeGetValue(
        dynamic colEnum, int encoding, bool checkBase64 = false, bool showIntValue = false)
    {
        try
        {
            object? value = colEnum.GetValue(encoding);
            if (value is null) return "null";
            if (showIntValue && value is int i)
                return $"Int32(0x{(uint)i:X8}, signed {i})";
            if (value is string s)
            {
                var report = $"string(length={s.Length})";
                if (checkBase64)
                {
                    try { report += $", base64 decodes to {Convert.FromBase64String(s).Length} bytes"; }
                    catch (FormatException) { report += ", NOT valid base64"; }
                }
                return report;
            }
            return value.GetType().Name;
        }
        catch (Exception ex)
        {
            return $"{ex.GetType().Name} 0x{Marshal.GetHRForException(ex):X8}";
        }
    }
}

internal static class NativeMethods
{
    [Flags]
    public enum CLSCTX : uint
    {
        INPROC_SERVER  = 0x1,
        INPROC_HANDLER = 0x2,
        LOCAL_SERVER   = 0x4,
        REMOTE_SERVER  = 0x10,
    }

    [DllImport("ole32.dll", ExactSpelling = true, PreserveSig = true)]
    public static extern int CoCreateInstance(
        ref Guid rclsid,
        IntPtr pUnkOuter,
        CLSCTX dwClsContext,
        ref Guid riid,
        out IntPtr ppv);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr LoadLibraryW(string lpLibFileName);
}

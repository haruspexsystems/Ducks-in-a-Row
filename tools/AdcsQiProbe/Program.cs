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

RunCoclass("CertRequestClass", new Guid("98aff3f0-5524-11d0-8812-00a0c903b83c"), iids);
Console.WriteLine();
RunCoclass("CertViewClass",    new Guid("a12d0f7a-1e84-11d1-9bd6-00c04fb683fa"), viewIids);

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
        int hr = Marshal.QueryInterface(unk, ref iidLocal, out IntPtr p);
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
// dynamic IDispatch path. Types and lengths only; no cell values are printed.
// For RawCertificate it additionally reports whether GetValue(Base64) yields a
// decodable base64 string, which is what the sync will rely on for SAN
// extraction.
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
        "RawCertificate",
    ];

    const int SchemaColumn = 0;         // ColumnType.Schema
    const int SeekEqual = 0x1;          // SeekOperator.Equal
    const int SortNone = 0x0;           // SortOrder.None
    const int DbDispositionIssued = 20; // DbDisposition.Issued
    const int EncodingBase64 = 0x1;     // OutputEncoding.Base64
    const int EncodingBinary = 0x2;     // OutputEncoding.Binary

    public static void Run(string caConfig)
    {
        object? raw = null;
        object? rowEnum = null;
        try
        {
            raw = Activator.CreateInstance(Type.GetTypeFromCLSID(CertViewClsid)!);
            dynamic view = raw!;
            view.OpenConnection(caConfig);

            view.SetResultColumnCount(Columns.Length);
            foreach (var col in Columns)
            {
                int idx = (int)view.GetColumnIndex(SchemaColumn, col);
                view.SetResultColumn(idx);
                Console.WriteLine($"  GetColumnIndex(Schema, \"{col}\") -> {idx}");
            }

            // Restrict to issued rows so row 1 carries a real certificate;
            // mirrors the sync's issued pass. A failure here is reported and
            // the probe continues unrestricted.
            try
            {
                int dispIdx = (int)view.GetColumnIndex(SchemaColumn, "Disposition");
                view.SetRestriction(dispIdx, SeekEqual, SortNone, DbDispositionIssued);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  SetRestriction(Disposition=20) failed: {ex.GetType().Name} 0x{Marshal.GetHRForException(ex):X8} — continuing unrestricted.");
            }

            rowEnum = view.OpenView();
            dynamic e = rowEnum!;
            if ((int)e.Next() == -1)
            {
                Console.WriteLine("  View returned no rows (no issued certificates on this CA?); nothing to read.");
                return;
            }

            object? colEnumObj = null;
            try
            {
                colEnumObj = e.EnumCertViewColumn();
                dynamic colEnum = colEnumObj!;
                Console.WriteLine($"  Row 1 result columns ({Columns.Length} requested):");
                while ((int)colEnum.Next() != -1)
                {
                    string name = (string)colEnum.GetName();
                    string binaryReport = DescribeGetValue(colEnum, EncodingBinary);
                    Console.WriteLine($"    GetName=\"{name}\"  GetValue(Binary) -> {binaryReport}");
                    if (name.EndsWith("RawCertificate", StringComparison.OrdinalIgnoreCase))
                    {
                        string base64Report = DescribeGetValue(colEnum, EncodingBase64, checkBase64: true);
                        Console.WriteLine($"      GetValue(Base64) -> {base64Report}");
                    }
                }
            }
            finally
            {
                if (colEnumObj != null && Marshal.IsComObject(colEnumObj))
                    Marshal.FinalReleaseComObject(colEnumObj);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  FAIL — {ex.GetType().Name}: 0x{Marshal.GetHRForException(ex):X8} {ex.Message}");
        }
        finally
        {
            if (rowEnum != null && Marshal.IsComObject(rowEnum)) Marshal.FinalReleaseComObject(rowEnum);
            if (raw != null && Marshal.IsComObject(raw)) Marshal.FinalReleaseComObject(raw);
        }
    }

    static string DescribeGetValue(dynamic colEnum, int encoding, bool checkBase64 = false)
    {
        try
        {
            object? value = colEnum.GetValue(encoding);
            if (value is null) return "null";
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

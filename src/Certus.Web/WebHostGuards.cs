using Certus.Core.Configuration;
using Serilog;

namespace Certus.Web;

/// <summary>
/// Startup guards for the Certus.Web host. Certus.Web is used for development and
/// integration testing and never wires a real ADCS client (that is Certus.Service's
/// job). These guards keep a misconfiguration from silently half-applying and then
/// failing deep in the host with an unhelpful error.
/// </summary>
public static class WebHostGuards
{
    /// <summary>
    /// Throws when a real CA is configured on the Certus.Web host. Certus.Web cannot
    /// honor one: it registers no real <c>IAdcsClient</c>, so the value would be accepted
    /// and then crash opaquely when the certificate sync hosted service is constructed.
    /// Fails fast with an actionable message instead.
    ///
    /// <para>
    /// Both places a CA connection string can come from are checked, and checking
    /// configuration alone is not enough (issue #305). The setup wizard never writes the
    /// CA back into appsettings.json; it persists it to the settings overlay in the data
    /// directory, and Certus.Web deliberately does not call <c>AddSettingsOverlay</c>, so
    /// the overlay is not a configuration source here. A fully configured installation
    /// therefore presents a null <c>Certus:CaConnectionString</c> to this host, a
    /// configuration only guard passes, and the dev host goes on to open the service's
    /// own database with the mock client behind it. Reading the overlay directly is what
    /// closes that.
    /// </para>
    ///
    /// <para>
    /// Configuration is checked first, so a developer who set the key themselves gets a
    /// message naming that key rather than a file they never touched. An overlay that
    /// cannot be read is not evidence of a configured CA, so it warns and allows startup
    /// rather than throwing; the same tolerance is applied to the alert overlay read in
    /// Program.cs.
    /// </para>
    ///
    /// <para>
    /// Takes the whole options object rather than a connection string so there is one
    /// entry point and no way to call the weaker check by accident.
    /// </para>
    /// </summary>
    public static void EnsureNoRealCaConfigured(CertusOptions options)
    {
        if (!string.IsNullOrEmpty(options.CaConnectionString))
        {
            throw new InvalidOperationException(
                "Certus:CaConnectionString is set, but Certus.Web does not host a real CA. " +
                "Run Certus.Service (the Windows Service host) for a real ADCS connection, " +
                "or clear Certus:CaConnectionString to run Certus.Web against the mock client.");
        }

        var overlayPath = SettingsOverlay.ResolvePath(options);

        string? overlayCaConnectionString;
        try
        {
            overlayCaConnectionString = SettingsOverlay.Load(overlayPath).CaConnectionString;
        }
        catch (Exception ex)
        {
            Log.Warning(
                ex,
                "The settings overlay at {OverlayPath} could not be read, so the dev host " +
                "cannot tell whether this machine has a real CA configured. Starting against " +
                "the mock client anyway",
                overlayPath);
            return;
        }

        if (!string.IsNullOrEmpty(overlayCaConnectionString))
        {
            throw new InvalidOperationException(
                $"The settings overlay at {overlayPath} configures a real CA, but Certus.Web " +
                "does not host one: it is the development host and always uses the mock ADCS " +
                "client. This looks like a configured Ducks in a Row installation, where " +
                "running the dev host would open the service's own database. Run the Ducks in " +
                "a Row service instead, or point Certus:SettingsOverlayPath somewhere else to " +
                "develop against the mock client.");
        }
    }
}

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
    /// Throws when a real CA connection string is configured on the Certus.Web host.
    /// Certus.Web cannot honor one: it registers no real <c>IAdcsClient</c>, so the
    /// value would be accepted and then crash opaquely when the certificate sync hosted
    /// service is constructed. Fails fast with an actionable message instead.
    /// </summary>
    public static void EnsureNoRealCaConfigured(string? caConnectionString)
    {
        if (!string.IsNullOrEmpty(caConnectionString))
        {
            throw new InvalidOperationException(
                "Certus:CaConnectionString is set, but Certus.Web does not host a real CA. " +
                "Run Certus.Service (the Windows Service host) for a real ADCS connection, " +
                "or clear Certus:CaConnectionString to run Certus.Web against the mock client.");
        }
    }
}

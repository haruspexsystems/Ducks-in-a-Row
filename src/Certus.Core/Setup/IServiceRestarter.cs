namespace Certus.Core.Setup;

/// <summary>
/// Applies setup configuration by restarting the host. The CA connection
/// string and external URL are read once at startup (singleton DI wiring), so
/// a restart is the apply mechanism after the wizard persists them.
/// </summary>
public interface IServiceRestarter
{
    /// <summary>
    /// Schedule a restart to happen shortly after the current request
    /// completes. Returns false when the hosting model cannot restart itself
    /// (console run, development host); the caller then tells the operator to
    /// restart manually.
    /// </summary>
    bool TryScheduleRestart();
}

/// <summary>
/// Restarter for hosts that cannot restart themselves (the development host
/// and console runs). Always reports false so the UI shows the manual step.
/// </summary>
public sealed class NoOpServiceRestarter : IServiceRestarter
{
    public bool TryScheduleRestart() => false;
}

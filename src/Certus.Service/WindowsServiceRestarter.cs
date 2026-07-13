using System.Diagnostics;
using Certus.Core.Setup;
using Microsoft.Extensions.Hosting.WindowsServices;

namespace Certus.Service;

/// <summary>
/// Restarts the Windows service to apply setup configuration. The restart runs
/// in a detached PowerShell child process: the SCM does not wrap services in a
/// kill on close job object, so the child survives this process stopping. The
/// two second delay lets the HTTP response that scheduled the restart flush
/// before Kestrel shuts down; the wizard then polls the anonymous setup status
/// endpoint until the service is back.
///
/// Deliberate details: stdout and stderr are not redirected (a pipe back to a
/// stopping parent can block the child), and the working directory is
/// System32 so the child never holds the install folder open.
/// </summary>
public sealed class WindowsServiceRestarter : IServiceRestarter
{
    /// <summary>
    /// The Windows service key name, matching ServiceInstall@Name in
    /// installer/Certus.wxs.
    /// </summary>
    public const string WindowsServiceName = "DucksInARow";

    private readonly ILogger<WindowsServiceRestarter> _logger;

    public WindowsServiceRestarter(ILogger<WindowsServiceRestarter> logger)
    {
        _logger = logger;
    }

    public bool TryScheduleRestart()
    {
        if (!WindowsServiceHelpers.IsWindowsService())
        {
            _logger.LogInformation(
                "Not running as a Windows service — configuration applies on the next manual restart");
            return false;
        }

        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments =
                    "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command " +
                    $"\"Start-Sleep -Seconds 2; Restart-Service -Name '{WindowsServiceName}' -Force\"",
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = Environment.SystemDirectory,
            };

            using var process = Process.Start(startInfo);
            if (process is null)
            {
                _logger.LogError("Failed to start the restart helper process");
                return false;
            }

            _logger.LogInformation(
                "Service restart scheduled (helper pid {Pid}); applying setup configuration",
                process.Id);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to schedule the service restart");
            return false;
        }
    }
}

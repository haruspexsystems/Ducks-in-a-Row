using System.Diagnostics;

namespace Certus.Core.Tests.Modules;

/// <summary>
/// Creates a directory junction for the reparse point refusal tests. A junction, unlike a
/// symbolic link, needs no privilege, so it works unelevated on the build runner.
/// </summary>
internal static class ReparsePoints
{
    public static bool TryCreateJunction(string link, string target)
    {
        var startInfo = new ProcessStartInfo("cmd.exe", $"/c mklink /J \"{link}\" \"{target}\"")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };

        using var process = Process.Start(startInfo);
        if (process is null)
            return false;

        process.WaitForExit();
        return process.ExitCode == 0 && Directory.Exists(link);
    }
}

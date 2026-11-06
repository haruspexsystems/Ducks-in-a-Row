using System.Text;
using Certus.Modules;
using Microsoft.Extensions.Logging;

namespace Certus.Core.Modules;

/// <summary>
/// A module's only way to write to the service log (licence design section 6.5). Module text is
/// untrusted, so every value has its control characters stripped and its length capped before it
/// reaches the log, the same defense <c>UrlCharacterGuardMiddleware</c> applies to request paths
/// against log forging.
/// </summary>
internal sealed class ModuleLog : IModuleLog
{
    private const int MaxCodeLength = 64;
    private const int MaxMessageLength = 1000;

    private readonly ILogger _logger;
    private readonly string _moduleId;

    public ModuleLog(ILogger logger, string moduleId)
    {
        _logger = logger;
        _moduleId = moduleId;
    }

    public void Write(ModuleLogLevel level, string code, string message)
    {
        var logLevel = level switch
        {
            ModuleLogLevel.Error => LogLevel.Error,
            ModuleLogLevel.Warning => LogLevel.Warning,
            _ => LogLevel.Information,
        };

        _logger.Log(logLevel, "Module {ModuleId} [{Code}]: {Message}",
            _moduleId, Sanitise(code, MaxCodeLength), Sanitise(message, MaxMessageLength));
    }

    private static string Sanitise(string? value, int cap)
    {
        if (string.IsNullOrEmpty(value))
            return string.Empty;

        var builder = new StringBuilder(Math.Min(value.Length, cap));
        foreach (var c in value)
        {
            if (builder.Length == cap)
                break;
            builder.Append(char.IsControl(c) ? ' ' : c);
        }

        return builder.ToString();
    }
}

/// <summary>
/// What the core hands a module at start (licence design section 12.7): its own protected state
/// folder under the data directory, and its sanitising log.
/// </summary>
internal sealed class ModuleContext : IModuleContext
{
    public ModuleContext(string stateDirectory, IModuleLog log)
    {
        StateDirectory = stateDirectory;
        Log = log;
    }

    public string StateDirectory { get; }

    public IModuleLog Log { get; }
}

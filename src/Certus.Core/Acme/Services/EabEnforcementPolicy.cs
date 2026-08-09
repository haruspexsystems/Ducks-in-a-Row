using Certus.Core.Configuration;
using Certus.Core.Setup;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Certus.Core.Acme.Services;

/// <summary>
/// External account binding enforcement mode (RFC 8555 §7.3.4).
/// </summary>
public enum EabEnforcementMode
{
    /// <summary>EAB is not enforced and a presented binding is ignored.</summary>
    Off,

    /// <summary>
    /// A presented binding is verified and recorded; registration without one
    /// is still allowed. The migration stage while credentials are handed out.
    /// </summary>
    Optional,

    /// <summary>
    /// New registrations must carry a valid binding. Accounts that already
    /// exist without one are grandfathered: they keep working and are flagged
    /// on the dashboard, where an administrator can deactivate them.
    /// </summary>
    Required
}

/// <summary>
/// Answers the current EAB enforcement mode. The mode lives in the wizard
/// status file (<see cref="SetupStatus.EabEnforcement"/>) and is read back the
/// same way <see cref="AllowedDomainsPolicy"/> reads its list: cached and
/// keyed on the file's last write time, so a settings change applies to the
/// next directory fetch and the next new-account without a service restart.
/// A missing file, a file written before the field existed, or an
/// unrecognized value all read as <see cref="EabEnforcementMode.Off"/>, so an
/// upgraded install stays unenforced until an administrator opts in.
/// </summary>
public sealed class EabEnforcementPolicy
{
    private readonly string _statusPath;
    private readonly ILogger<EabEnforcementPolicy> _logger;
    private readonly object _lock = new();
    private EabEnforcementMode _mode = EabEnforcementMode.Off;
    private DateTime _loadedWriteTimeUtc;
    private bool _loaded;

    public EabEnforcementPolicy(
        IOptions<CertusOptions> options,
        ILogger<EabEnforcementPolicy> logger)
    {
        _statusPath = SetupStatus.GetStatusPath(options.Value);
        _logger = logger;
    }

    /// <summary>The enforcement mode in effect for the current request.</summary>
    public EabEnforcementMode Mode => GetMode();

    /// <summary>
    /// Strict parse of an administrator supplied mode string. Unlike the
    /// loader below, an unrecognized value is a validation failure here, not
    /// a silent Off, so the settings API can refuse a typo.
    /// </summary>
    public static bool TryParseMode(string? value, out EabEnforcementMode mode)
    {
        switch (value?.Trim().ToLowerInvariant())
        {
            case "off":
                mode = EabEnforcementMode.Off;
                return true;
            case "optional":
                mode = EabEnforcementMode.Optional;
                return true;
            case "required":
                mode = EabEnforcementMode.Required;
                return true;
            default:
                mode = EabEnforcementMode.Off;
                return false;
        }
    }

    /// <summary>The canonical lowercase name of a mode, as persisted and served.</summary>
    public static string ModeName(EabEnforcementMode mode)
    {
        return mode switch
        {
            EabEnforcementMode.Optional => "optional",
            EabEnforcementMode.Required => "required",
            _ => "off",
        };
    }

    private EabEnforcementMode GetMode()
    {
        var writeTime = File.GetLastWriteTimeUtc(_statusPath);
        lock (_lock)
        {
            if (_loaded && writeTime == _loadedWriteTimeUtc)
                return _mode;

            if (!SetupStatus.TryLoad(_statusPath, out var status))
            {
                // The file exists but could not be read right now (a transient
                // lock from a scanner or backup, or a torn write). Keep the
                // last known mode for this request and retry on the next one,
                // matching AllowedDomainsPolicy: caching a decision against
                // the new write time would make a momentary read failure last.
                _logger.LogWarning(
                    "Could not read {Path}; keeping the last known EAB enforcement mode for this request",
                    _statusPath);
                return _mode;
            }

            var previous = _loaded ? _mode : (EabEnforcementMode?)null;
            _mode = ParseLoaded(status.EabEnforcement);
            _loadedWriteTimeUtc = writeTime;
            _loaded = true;

            if (previous != _mode)
            {
                _logger.LogInformation(
                    "EAB enforcement mode loaded from {Path}: {Mode}",
                    _statusPath, ModeName(_mode));
            }

            return _mode;
        }
    }

    private EabEnforcementMode ParseLoaded(string? value)
    {
        // Absent is the legitimate pre-EAB state and stays quiet; a present
        // but unrecognized value is a hand edit worth saying something about.
        if (string.IsNullOrWhiteSpace(value))
            return EabEnforcementMode.Off;

        if (TryParseMode(value, out var mode))
            return mode;

        _logger.LogWarning(
            "Unrecognized EAB enforcement mode '{Value}' in {Path}; treating it as off until the value is fixed",
            value, _statusPath);
        return EabEnforcementMode.Off;
    }
}

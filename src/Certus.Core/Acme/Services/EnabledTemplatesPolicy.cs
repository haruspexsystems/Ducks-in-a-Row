using Certus.Core.Adcs;
using Certus.Core.Configuration;
using Certus.Core.Setup;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Certus.Core.Acme.Services;

/// <summary>
/// Answers whether a certificate template is enabled for ACME. The setup wizard
/// records the administrator's template choice in the wizard status file
/// (<see cref="SetupStatus.EnabledTemplates"/>); this policy reads it back so
/// the runtime honours the wizard's promise (issue #85).
///
/// A missing status file or an empty list means no restriction: installs
/// configured before the wizard existed, or straight from appsettings, keep
/// exposing every template the CA publishes. The wizard requires at least one
/// template at completion, so a non empty list is the only restricting state.
/// </summary>
public sealed class EnabledTemplatesPolicy
{
    private readonly string _statusPath;
    private readonly ILogger<EnabledTemplatesPolicy> _logger;
    private readonly object _lock = new();
    private HashSet<string>? _enabled;
    private DateTime _loadedWriteTimeUtc;
    private bool _loaded;

    public EnabledTemplatesPolicy(
        IOptions<CertusOptions> options,
        ILogger<EnabledTemplatesPolicy> logger)
    {
        _statusPath = SetupStatus.GetStatusPath(options.Value);
        _logger = logger;
    }

    /// <summary>
    /// True when the template may be served via ACME. An enabled entry matches
    /// the programmatic name or the display name, case insensitive, consistent
    /// with the dual form resolution from issue #17. The wizard writes the
    /// programmatic name; the display form is accepted for hand edited files.
    /// </summary>
    public bool IsEnabled(TemplateInfo template)
    {
        var enabled = GetEnabledSet();
        return enabled == null
            || enabled.Contains(template.Name)
            || enabled.Contains(template.DisplayName);
    }

    /// <summary>
    /// The enabled set, or null when there is no restriction. Cached and keyed
    /// on the status file's last write time so a wizard re run takes effect
    /// without a restart. File.GetLastWriteTimeUtc returns a fixed sentinel for
    /// a missing file, so one stat call also covers the file appearing or
    /// disappearing.
    /// </summary>
    private HashSet<string>? GetEnabledSet()
    {
        var writeTime = File.GetLastWriteTimeUtc(_statusPath);
        lock (_lock)
        {
            if (_loaded && writeTime == _loadedWriteTimeUtc)
                return _enabled;

            var status = SetupStatus.Load(_statusPath);
            _enabled = status.EnabledTemplates is { Count: > 0 }
                ? new HashSet<string>(status.EnabledTemplates, StringComparer.OrdinalIgnoreCase)
                : null;
            _loadedWriteTimeUtc = writeTime;
            _loaded = true;

            if (_enabled == null && File.Exists(_statusPath))
                // The file is there but carried no usable set. That is either
                // pre wizard state or a file SetupStatus.Load could not parse
                // (its catch returns an empty status), so say it loudly: the
                // template restriction is off.
                _logger.LogWarning(
                    "Status file {Path} exists but no enabled template set could be read; " +
                    "all CA published templates are exposed via ACME",
                    _statusPath);
            else if (_enabled == null)
                _logger.LogInformation(
                    "No enabled template set recorded in {Path}; " +
                    "all CA published templates are exposed via ACME",
                    _statusPath);
            else
                _logger.LogInformation(
                    "ACME template policy loaded from {Path}: {Count} enabled ({Templates})",
                    _statusPath, _enabled.Count, string.Join(", ", _enabled));

            return _enabled;
        }
    }
}

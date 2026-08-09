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
/// The policy fails closed (issue #101): until a non empty enabled set is
/// recorded, no template is exposed. A missing status file, a file with no
/// usable set, and a file that cannot be read all expose nothing; an
/// unreadable file keeps the last known set for the current request without
/// caching, so a torn write can narrow exposure but never widen it. The only
/// way to expose every CA published template is the explicit break-glass
/// override <see cref="AcmeOptions.ExposeAllTemplates"/>, which wins over a
/// recorded set and is named in a warning on every boot by
/// <see cref="Security.StartupValidator"/>.
/// </summary>
public sealed class EnabledTemplatesPolicy
{
    private readonly string _statusPath;
    private readonly bool _exposeAllTemplates;
    private readonly ILogger<EnabledTemplatesPolicy> _logger;
    private readonly object _lock = new();
    private HashSet<string>? _enabled;
    private DateTime _loadedWriteTimeUtc;
    private bool _loaded;

    public EnabledTemplatesPolicy(
        IOptions<CertusOptions> options,
        IOptions<AcmeOptions> acmeOptions,
        ILogger<EnabledTemplatesPolicy> logger)
    {
        _statusPath = SetupStatus.GetStatusPath(options.Value);
        _exposeAllTemplates = acmeOptions.Value.ExposeAllTemplates;
        _logger = logger;
    }

    /// <summary>
    /// True when the template may be served via ACME. An enabled entry matches
    /// the programmatic name or the display name, case insensitive, consistent
    /// with the dual form resolution from issue #17. The wizard writes the
    /// programmatic name; the display form is accepted for hand edited files.
    /// With no enabled set recorded this returns false for every template,
    /// unless the break-glass override is set.
    /// </summary>
    public bool IsEnabled(TemplateInfo template)
    {
        if (_exposeAllTemplates)
            return true;

        var enabled = GetEnabledSet();
        return enabled != null
            && (enabled.Contains(template.Name)
                || enabled.Contains(template.DisplayName));
    }

    /// <summary>
    /// The enabled set, or null when no usable set is recorded, which exposes
    /// nothing. Cached and keyed on the status file's last write time so a
    /// wizard re run takes effect without a restart. File.GetLastWriteTimeUtc
    /// returns a fixed sentinel for a missing file, so one stat call also
    /// covers the file appearing or disappearing.
    /// </summary>
    private HashSet<string>? GetEnabledSet()
    {
        var writeTime = File.GetLastWriteTimeUtc(_statusPath);
        lock (_lock)
        {
            if (_loaded && writeTime == _loadedWriteTimeUtc)
                return _enabled;

            if (!SetupStatus.TryLoad(_statusPath, out var status))
            {
                // The file exists but could not be read or parsed right now.
                // Do not cache against the new write time: answer from the
                // last known state and retry on the next request. That state
                // is either a previously loaded set or the closed default,
                // never allow all, so a failure here can narrow exposure but
                // never widen it.
                if (_enabled != null)
                    _logger.LogError(
                        "Could not read {Path}; keeping the last known enabled template " +
                        "set ({Count} templates) for this request",
                        _statusPath, _enabled.Count);
                else
                    _logger.LogError(
                        "Could not read {Path}; no templates are exposed via ACME until " +
                        "the file is fixed or the setup wizard is re-run",
                        _statusPath);
                return _enabled;
            }

            _enabled = status.EnabledTemplates is { Count: > 0 }
                ? new HashSet<string>(status.EnabledTemplates, StringComparer.OrdinalIgnoreCase)
                : null;
            _loadedWriteTimeUtc = writeTime;
            _loaded = true;

            if (_enabled != null)
                _logger.LogInformation(
                    "ACME template policy loaded from {Path}: {Count} enabled ({Templates})",
                    _statusPath, _enabled.Count, string.Join(", ", _enabled));
            else if (File.Exists(_statusPath))
                _logger.LogWarning(
                    "Status file {Path} exists but records no enabled template set; " +
                    "no templates are exposed via ACME",
                    _statusPath);
            else
                _logger.LogInformation(
                    "No wizard status file at {Path}; no templates are exposed via ACME " +
                    "until the setup wizard completes",
                    _statusPath);

            return _enabled;
        }
    }
}

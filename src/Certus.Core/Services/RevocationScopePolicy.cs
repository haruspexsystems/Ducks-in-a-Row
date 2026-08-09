using Certus.Core.Configuration;
using Certus.Core.Setup;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Certus.Core.Services;

/// <summary>
/// Which certificates the dashboard may revoke, under the TLS capability
/// ceiling (the ceiling is unconditional; the scope only ever narrows
/// within it).
/// </summary>
public enum RevocationScopeMode
{
    /// <summary>
    /// The default and the recommendation: certificates Ducks issued through
    /// ACME, plus certificates on the currently enabled ACME templates.
    /// </summary>
    DucksManaged,

    /// <summary>Certificates on an administrator selected template list.</summary>
    Custom,

    /// <summary>Any certificate the ceiling allows.</summary>
    All
}

/// <summary>
/// One consistent view of the revocation scope, taken from a single file
/// load (the AllowedDomainsPolicy snapshot stance): the mode, the custom
/// template list, and the enabled template set all come from the same read,
/// so a file rewrite during a request cannot mix an old mode with a new
/// list. EnabledTemplates deliberately comes straight from the status file
/// rather than through EnabledTemplatesPolicy: the
/// Certus:Acme:ExposeAllTemplates break glass widens ACME exposure and must
/// never widen what the dashboard may revoke.
/// </summary>
public sealed record RevocationScopeSnapshot(
    RevocationScopeMode Mode,
    IReadOnlyList<string> CustomTemplates,
    IReadOnlyList<string> EnabledTemplates);

/// <summary>
/// Answers the current dashboard revocation scope. The mode and the custom
/// template list live in the wizard status file
/// (<see cref="SetupStatus.RevocationScope"/> and
/// <see cref="SetupStatus.RevocableTemplates"/>) and are read back the same
/// way <see cref="Certus.Core.Acme.Services.EabEnforcementPolicy"/> reads
/// its mode: cached and keyed on the file's last write time, so a settings
/// change applies to the next revocation attempt without a restart. A
/// missing file, a file written before the fields existed, or an
/// unrecognized value all read as <see cref="RevocationScopeMode.DucksManaged"/>,
/// the safe default, so an upgraded install starts narrow.
/// </summary>
public sealed class RevocationScopePolicy
{
    private readonly string _statusPath;
    private readonly ILogger<RevocationScopePolicy> _logger;
    private readonly object _lock = new();
    private RevocationScopeSnapshot _snapshot = new(RevocationScopeMode.DucksManaged, [], []);
    private DateTime _loadedWriteTimeUtc;
    private bool _loaded;

    public RevocationScopePolicy(
        IOptions<CertusOptions> options,
        ILogger<RevocationScopePolicy> logger)
    {
        _statusPath = SetupStatus.GetStatusPath(options.Value);
        _logger = logger;
    }

    /// <summary>
    /// Strict parse of an administrator supplied mode string. Unlike the
    /// loader below, an unrecognized value is a validation failure here, not
    /// a silent default, so the settings API can refuse a typo.
    /// </summary>
    public static bool TryParseMode(string? value, out RevocationScopeMode mode)
    {
        switch (value?.Trim().ToLowerInvariant())
        {
            case "ducks-managed":
                mode = RevocationScopeMode.DucksManaged;
                return true;
            case "custom":
                mode = RevocationScopeMode.Custom;
                return true;
            case "all":
                mode = RevocationScopeMode.All;
                return true;
            default:
                mode = RevocationScopeMode.DucksManaged;
                return false;
        }
    }

    /// <summary>The canonical lowercase name of a mode, as persisted and served.</summary>
    public static string ModeName(RevocationScopeMode mode)
    {
        return mode switch
        {
            RevocationScopeMode.Custom => "custom",
            RevocationScopeMode.All => "all",
            _ => "ducks-managed",
        };
    }

    /// <summary>
    /// The scope in effect for the current decision. Callers take one
    /// snapshot per decision and read everything from it.
    /// </summary>
    public RevocationScopeSnapshot GetSnapshot()
    {
        var writeTime = File.GetLastWriteTimeUtc(_statusPath);
        lock (_lock)
        {
            if (_loaded && writeTime == _loadedWriteTimeUtc)
                return _snapshot;

            if (!SetupStatus.TryLoad(_statusPath, out var status))
            {
                // The file exists but could not be read right now (a transient
                // lock from a scanner or backup, or a torn write). Keep the
                // last known snapshot for this decision and retry on the next,
                // without caching against the new write time, matching
                // AllowedDomainsPolicy.
                _logger.LogWarning(
                    "Could not read {Path}; keeping the last known revocation scope for this decision",
                    _statusPath);
                return _snapshot;
            }

            var previous = _loaded ? _snapshot : null;
            _snapshot = new RevocationScopeSnapshot(
                ParseLoaded(status.RevocationScope),
                status.RevocableTemplates.AsReadOnly(),
                status.EnabledTemplates.AsReadOnly());
            _loadedWriteTimeUtc = writeTime;
            _loaded = true;

            // A list only change is as much of a scope change as a mode
            // change, and this may be the other host picking up an edit made
            // through its sibling, so it deserves its own log line.
            if (previous == null ||
                previous.Mode != _snapshot.Mode ||
                !previous.CustomTemplates.SequenceEqual(
                    _snapshot.CustomTemplates, StringComparer.OrdinalIgnoreCase))
            {
                _logger.LogInformation(
                    "Revocation scope loaded from {Path}: {Mode} ({CustomCount} custom templates)",
                    _statusPath, ModeName(_snapshot.Mode), _snapshot.CustomTemplates.Count);
            }

            return _snapshot;
        }
    }

    private RevocationScopeMode ParseLoaded(string? value)
    {
        // Absent is the legitimate pre-feature state and stays quiet; a
        // present but unrecognized value is a hand edit worth saying
        // something about. Both read as the narrow default, so a bad value
        // can only ever shrink what is revocable, never widen it.
        if (string.IsNullOrWhiteSpace(value))
            return RevocationScopeMode.DucksManaged;

        if (TryParseMode(value, out var mode))
            return mode;

        _logger.LogWarning(
            "Unrecognized revocation scope '{Value}' in {Path}; treating it as ducks-managed until the value is fixed",
            value, _statusPath);
        return RevocationScopeMode.DucksManaged;
    }
}

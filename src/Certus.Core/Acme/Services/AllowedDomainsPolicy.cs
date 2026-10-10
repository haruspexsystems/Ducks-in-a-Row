using System.Globalization;
using System.Net;
using Certus.Core.Acme.Models;
using Certus.Core.Configuration;
using Certus.Core.Setup;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Certus.Core.Acme.Services;

/// <summary>
/// Answers whether ACME order identifiers fall inside the administrator's
/// allowed domain list. The list lives in the wizard status file
/// (<see cref="SetupStatus.AllowedDomains"/>) next to the enabled template
/// choice, and is read back the same way <see cref="EnabledTemplatesPolicy"/>
/// reads its set: cached and keyed on the file's last write time, so a
/// settings page edit applies to the next order without a service restart.
///
/// An entry covers the domain itself and every subdomain beneath it, on
/// label boundaries: corp.example.com matches web.corp.example.com and
/// a.b.corp.example.com, never mycorp.example.com. A wildcard identifier
/// *.D is allowed exactly when D would be, because every name such a
/// certificate can cover sits under D.
/// Names and entries are compared after normalization to lowercase punycode
/// A labels, so a Unicode name and its A label form are the same name here.
///
/// A missing status file, the enabled flag off, or an enabled flag with no
/// usable entries all mean no restriction. The settings API refuses to save
/// the enabled flag without at least one usable entry, so that last state
/// only arises from hand edits; it fails open with a loud warning. That is a
/// deliberate contrast with <see cref="EnabledTemplatesPolicy"/>, which fails
/// closed since issue #101: the domain restriction is opt in, while template
/// exposure is the issuance gate itself.
/// </summary>
public sealed class AllowedDomainsPolicy
{
    private static readonly IdnMapping Idn = new();

    private readonly string _statusPath;
    private readonly ILogger<AllowedDomainsPolicy> _logger;
    private readonly object _lock = new();
    private List<string>? _entries;
    private DateTime _loadedWriteTimeUtc;
    private bool _loaded;

    public AllowedDomainsPolicy(
        IOptions<CertusOptions> options,
        ILogger<AllowedDomainsPolicy> logger)
    {
        _statusPath = SetupStatus.GetStatusPath(options.Value);
        _logger = logger;
    }

    /// <summary>
    /// The identifier values the current policy refuses, in request order.
    /// Empty when the policy is inactive or every identifier is allowed.
    /// The entry snapshot is taken once per call, so a file rewrite during
    /// a request cannot mix the old and the new list within one decision.
    /// </summary>
    public IReadOnlyList<string> FindDisallowed(IEnumerable<AcmeIdentifier> identifiers)
    {
        var entries = GetEntries();
        if (entries == null)
            return Array.Empty<string>();

        return FindDisallowedAgainst(identifiers, entries);
    }

    /// <summary>
    /// The identifier values a normalized entry list refuses, in request
    /// order. This is the one matcher shared by the global policy above and
    /// the per credential EAB namespaces, so the two cannot drift: *.D is
    /// allowed exactly when D is, names are compared as lowercase punycode A
    /// labels on label boundaries, and an unparseable name is refused. An
    /// empty entry list refuses every identifier; a caller that means "no
    /// restriction" must not call at all, the way FindDisallowed maps its
    /// inactive states to null entries and the EAB namespace check skips
    /// credentials with an empty namespace.
    /// </summary>
    public static IReadOnlyList<string> FindDisallowedAgainst(
        IEnumerable<AcmeIdentifier> identifiers,
        IReadOnlyList<string> normalizedEntries)
    {
        var disallowed = new List<string>();
        foreach (var id in identifiers)
        {
            // Wildcard rule: *.D is allowed exactly when D would be. Strip
            // the marker once, the same way OrderController screens literals.
            var name = id.Value.StartsWith("*.", StringComparison.Ordinal)
                ? id.Value[2..]
                : id.Value;

            if (!TryNormalizeDomain(name, out var normalized)
                || !normalizedEntries.Any(entry => MatchesEntry(normalized, entry)))
            {
                disallowed.Add(id.Value);
            }
        }

        return disallowed;
    }

    /// <summary>
    /// Normalize a domain name for comparison: trim, strip one trailing dot,
    /// lowercase, and convert to punycode A labels. The IDN conversion also
    /// rejects structurally invalid names (empty labels, labels over 63
    /// octets, names over the DNS length limit) for free.
    /// </summary>
    public static bool TryNormalizeDomain(string raw, out string normalized)
    {
        normalized = string.Empty;

        var value = raw.Trim();
        if (value.EndsWith('.'))
            value = value[..^1];
        if (value.Length == 0)
            return false;

        try
        {
            normalized = Idn.GetAscii(value.ToLowerInvariant()).ToLowerInvariant();
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    /// <summary>
    /// Validate one administrator entered entry. Returns null and the
    /// normalized form when the entry is usable, otherwise a plain language
    /// reason for the settings page to show.
    /// </summary>
    public static string? ValidateEntry(string raw, out string normalized)
    {
        normalized = string.Empty;
        var value = raw.Trim();

        if (value.Length == 0)
            return "Enter a domain name.";
        if (value.Contains('*'))
            return "Do not use wildcards here. Subdomains of an allowed domain are included automatically.";
        if (value.Contains("://", StringComparison.Ordinal))
            return "Enter a bare domain name without a scheme, for example corp.example.com.";
        if (value.Contains('/'))
            return "Enter a domain name without a path.";
        if (value.Any(char.IsWhiteSpace))
            return "Domain names cannot contain spaces.";

        var bare = value.StartsWith('[') && value.EndsWith(']') ? value[1..^1] : value;
        if (IPAddress.TryParse(bare, out _))
            return "IP addresses are not allowed. Enter a domain name.";
        if (value.Contains(':'))
            return "Enter a domain name without a port.";

        if (!TryNormalizeDomain(value, out normalized))
            return "This is not a valid domain name.";

        return null;
    }

    /// <summary>
    /// Whether a normalized name is covered by a normalized entry: the name
    /// is the entry itself or any subdomain of it. The mandatory dot before
    /// the entry is the label boundary guard that keeps corp.example.com
    /// from matching mycorp.example.com.
    /// </summary>
    public static bool MatchesEntry(string normalizedName, string normalizedEntry)
    {
        return normalizedName == normalizedEntry
            || normalizedName.EndsWith("." + normalizedEntry, StringComparison.Ordinal);
    }

    /// <summary>
    /// Validate and normalize a whole entry list: normalized entries in
    /// first occurrence order with duplicates collapsed, plus the entries
    /// that were refused and why. The one definition of the list level
    /// semantics, shared by the settings API, setup completion, and the
    /// policy loader, so the three cannot drift on what counts as the same
    /// domain.
    /// </summary>
    public static (List<string> Normalized, List<(string Entry, string Reason)> Invalid)
        ValidateAndNormalize(IEnumerable<string> entries)
    {
        var normalized = new List<string>();
        var invalid = new List<(string Entry, string Reason)>();
        foreach (var entry in entries)
        {
            var reason = ValidateEntry(entry, out var normalizedEntry);
            if (reason != null)
                invalid.Add((entry, reason));
            else if (!normalized.Contains(normalizedEntry))
                normalized.Add(normalizedEntry);
        }

        return (normalized, invalid);
    }

    /// <summary>
    /// The normalized entry list, or null when there is no restriction.
    /// Cached and keyed on the status file's last write time, like
    /// <see cref="EnabledTemplatesPolicy"/>: File.GetLastWriteTimeUtc returns
    /// a fixed sentinel for a missing file, so one stat call also covers the
    /// file appearing or disappearing.
    /// </summary>
    private List<string>? GetEntries()
    {
        var writeTime = File.GetLastWriteTimeUtc(_statusPath);
        lock (_lock)
        {
            if (_loaded && writeTime == _loadedWriteTimeUtc)
                return _entries;

            if (!SetupStatus.TryLoad(_statusPath, out var status))
            {
                // The file exists but could not be read right now (a
                // transient lock from a scanner or backup, or a torn write).
                // Do not cache a decision against the new write time: keep
                // the last known policy for this order and retry on the next
                // one. Caching here would silently turn a momentary read
                // failure into a lasting fail open.
                _logger.LogWarning(
                    "Could not read {Path}; keeping the last known domain restriction for this order",
                    _statusPath);
                return _entries;
            }

            _entries = BuildEntries(status);
            _loadedWriteTimeUtc = writeTime;
            _loaded = true;
            return _entries;
        }
    }

    private List<string>? BuildEntries(SetupStatus status)
    {
        if (!status.AllowedDomainsEnabled)
        {
            _logger.LogInformation(
                "Domain restriction is off in {Path}; orders may name any domain",
                _statusPath);
            return null;
        }

        var (entries, invalid) = ValidateAndNormalize(status.AllowedDomains);
        foreach (var (entry, reason) in invalid)
        {
            _logger.LogWarning(
                "Skipping unusable allowed domain entry '{Entry}' in {Path}: {Reason}",
                entry, _statusPath, reason);
        }

        if (entries.Count == 0)
        {
            // Only reachable by hand editing the file: the settings API and
            // the wizard refuse to save the enabled flag without at least one
            // usable entry. Refusing every order would be the worse failure
            // mode, so fail open and say it loudly.
            _logger.LogWarning(
                "Domain restriction is enabled in {Path} but no usable entries were found; " +
                "the restriction is off until the list is fixed",
                _statusPath);
            return null;
        }

        _logger.LogInformation(
            "Domain restriction loaded from {Path}: {Count} allowed ({Domains})",
            _statusPath, entries.Count, string.Join(", ", entries));
        return entries;
    }
}

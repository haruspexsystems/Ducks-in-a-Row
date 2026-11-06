using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Microsoft.Extensions.Logging;

namespace Certus.Core.Audit;

/// <summary>
/// The one writer of <see cref="AdminAuditEntry"/> rows (issue #634). See
/// <see cref="IAdminAuditTrail"/> for the contract.
///
/// <para>Values are cut to the declared column widths here, because every
/// string column is TEXT in SQLite and EF checks no length on save
/// (<c>.claude/rules/ef-data.md</c>). The widths are generous for words and
/// far too short for a key or a certificate, which is a second guard against a
/// controller handing over something it should not.</para>
/// </summary>
public sealed class AdminAuditTrail : IAdminAuditTrail
{
    /// <summary>Declared width of <see cref="AdminAuditEntry.Actor"/>: a DOMAIN\name or a UPN.</summary>
    public const int MaxActorLength = 256;

    /// <summary>Declared width of <see cref="AdminAuditEntry.Action"/>.</summary>
    public const int MaxActionLength = 100;

    /// <summary>Declared width of <see cref="AdminAuditEntry.Target"/>.</summary>
    public const int MaxTargetLength = 500;

    /// <summary>Declared width of the before and after columns.</summary>
    public const int MaxValueLength = 4000;

    /// <summary>What an actor with no name is recorded as: the Development only Auth:Mode=Disabled escape hatch.</summary>
    public const string AnonymousActor = "(anonymous)";

    /// <summary>What a missing value reads as in the log line, so the line is never ambiguous about an empty field.</summary>
    internal const string None = "(none)";

    private readonly CertusDbContext _db;
    private readonly ILogger<AdminAuditTrail> _logger;
    private readonly TimeProvider _time;

    public AdminAuditTrail(
        CertusDbContext db,
        ILogger<AdminAuditTrail> logger,
        TimeProvider? timeProvider = null)
    {
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _time = timeProvider ?? TimeProvider.System;
    }

    /// <inheritdoc />
    public int Recorded { get; private set; }

    /// <inheritdoc />
    public async Task<AdminAuditEntry> RecordAsync(
        AdminAuditEvent auditEvent, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(auditEvent);
        if (string.IsNullOrWhiteSpace(auditEvent.Action))
            throw new ArgumentException("An audit event needs an action name.", nameof(auditEvent));

        var entry = new AdminAuditEntry
        {
            OccurredAt = _time.GetUtcNow().UtcDateTime,
            Actor = Bound(auditEvent.Actor, MaxActorLength) ?? AnonymousActor,
            Action = Bound(auditEvent.Action, MaxActionLength)!,
            Target = Bound(auditEvent.Target, MaxTargetLength),
            BeforeValue = Bound(auditEvent.Before, MaxValueLength),
            AfterValue = Bound(auditEvent.After, MaxValueLength),
        };

        _db.AdminAuditEntries.Add(entry);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        Recorded++;

        // Warning on purpose (the Decision on #634): an operator who raises the
        // minimum level to Warning to quieten the log still gets every
        // administrator action, and the row above is written whatever the level.
        _logger.LogWarning(
            "Administrator action {Action} by {Actor}: target {Target}, before {Before}, after {After}",
            entry.Action, entry.Actor, entry.Target ?? None, entry.BeforeValue ?? None, entry.AfterValue ?? None);

        return entry;
    }

    /// <summary>Trims and cuts a value to a column width; null and blank stay null.</summary>
    internal static string? Bound(string? value, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;
        var trimmed = value.Trim();
        return trimmed.Length <= maxLength ? trimmed : trimmed[..maxLength];
    }
}

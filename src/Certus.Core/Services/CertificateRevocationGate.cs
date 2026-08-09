using System.Collections.Concurrent;
using Certus.Core.Adcs;

namespace Certus.Core.Services;

/// <summary>
/// Serializes revocation attempts per certificate serial (issue #203).
///
/// <para>
/// <see cref="CertificateRevocationService.RevokeAsync"/> is a check then act
/// sequence: read the inventory row, refuse if it is already revoked, call the
/// CA. Two requests for the same certificate arriving together (two admins,
/// two tabs, a client retry racing the original) could both read the row as
/// Issued, both pass every guard, and both send the CA a revocation, which the
/// acceptance criteria for issue #159 forbid. This gate parks the loser until
/// the winner's floor write has landed, so the loser re-reads a row that
/// already says Revoked and is refused without a CA call.
/// </para>
///
/// <para>Four properties are deliberate and worth stating:</para>
/// <list type="bullet">
/// <item>
/// <b>It is keyed on the claimed serial, not the row serial.</b> Any two
/// requests that could both reach the CA for one row must both pass the
/// target mismatch guard, which proves their claimed serials normalize equal
/// to the row's, so they always share a key. A request claiming the wrong
/// serial takes a different key and is refused by that guard without a CA
/// call, so nothing is lost by keying on the claim.
/// </item>
/// <item>
/// <b>It is held across the CA call and the in request resync.</b> A full CA
/// pull under the gate costs seconds, which is acceptable for an action this
/// rare; releasing before the floor write would reopen the window this gate
/// exists to close. This is a separate lock from CertificateSyncService's own
/// sync gate, and the order is always revocation gate first, sync gate second,
/// so the two cannot deadlock.
/// </item>
/// <item>
/// <b>Entries are never evicted.</b> The dictionary grows by one small
/// semaphore per distinct serial an admin attempts to revoke in one process
/// lifetime, which is bounded and tiny, and eviction would reintroduce the
/// removal race this class exists to end.
/// </item>
/// <item>
/// <b>It is per process.</b> Ducks runs as a single Windows service host, so
/// that is the whole installation. It is not a distributed lock and is not
/// trying to be.
/// </item>
/// </list>
/// </summary>
public sealed class CertificateRevocationGate
{
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _gates =
        new(StringComparer.Ordinal);

    /// <summary>
    /// Acquires the gate for the given claimed serial; dispose the returned
    /// handle to release it. A null or blank claim maps to one shared
    /// degenerate key rather than throwing: such a request can never reach the
    /// CA (the target mismatch guard refuses it first), so briefly waiting on
    /// a shared gate is harmless.
    /// </summary>
    public async Task<IDisposable> AcquireAsync(
        string? claimedSerial, CancellationToken cancellationToken)
    {
        var key = string.IsNullOrWhiteSpace(claimedSerial)
            ? string.Empty
            : SerialNumbers.Normalize(claimedSerial);

        // A GetOrAdd racer that loses leaks one undisposed SemaphoreSlim;
        // without a WaitHandle access it holds no unmanaged state, so that
        // is fine.
        var gate = _gates.GetOrAdd(key, _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(cancellationToken);
        return new Releaser(gate);
    }

    private sealed class Releaser : IDisposable
    {
        private SemaphoreSlim? _gate;

        public Releaser(SemaphoreSlim gate) => _gate = gate;

        public void Dispose() => Interlocked.Exchange(ref _gate, null)?.Release();
    }
}

using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Certus.Core.Acme.Services;

/// <summary>
/// Computes the suggested renewal window an ARI response carries (RFC 9773
/// §4.2). The RFC leaves the policy to the server; this is the single home
/// for ours, the way <see cref="Attestation.AppleAttestationOids"/> is for the
/// attestation constants.
///
/// The window sits at two thirds of the certificate's lifetime, is 2% of that
/// lifetime wide (never narrower than an hour, never wider than a third of the
/// lifetime), and is shifted by a jitter derived deterministically from the
/// serial number, so a fleet issued in one batch does not renew in one batch.
/// Every arm anchors on facts about the certificate alone (its validity, its
/// revocation instant), never on the clock, so the window a client sees never
/// moves between polls. A revoked certificate gets a window entirely before
/// its revocation instant, which is the RFC's client side "renew immediately"
/// signal (§4.2 step 3).
///
/// Invariant, and the one MUST the RFC states for servers: the end always
/// falls strictly after the start, by more than the whole second the wire
/// format truncates to.
/// </summary>
public static class RenewalWindowPolicy
{
    /// <summary>
    /// The Retry-After value (RFC 9773 §4.3) on every renewal info response.
    /// It bounds how quickly a polling fleet notices a revocation driven
    /// window change.
    /// </summary>
    public static readonly TimeSpan RetryAfter = TimeSpan.FromHours(6);

    private static readonly TimeSpan MinimumWidth = TimeSpan.FromHours(1);

    /// <summary>
    /// Below this lifetime the fraction arithmetic degenerates: a width under
    /// a couple of seconds could serialize as start == end once the wire form
    /// truncates to whole seconds, which the RFC forbids. Such a certificate
    /// is answered renew now instead.
    /// </summary>
    private static readonly TimeSpan MinimumLifetime = TimeSpan.FromSeconds(30);

    public static (DateTimeOffset Start, DateTimeOffset End) GetWindow(
        DateTimeOffset notBefore, DateTimeOffset notAfter, DateTimeOffset? revokedAt,
        ReadOnlySpan<byte> serialNumber)
    {
        if (revokedAt is { } revocationInstant)
            return PastWindowAnchoredOn(revocationInstant);

        var lifetime = notAfter - notBefore;
        if (lifetime < MinimumLifetime)
            return PastWindowAnchoredOn(notAfter);

        var widthTicks = Math.Max(lifetime.Ticks / 50, MinimumWidth.Ticks);
        widthTicks = Math.Min(widthTicks, lifetime.Ticks / 3);

        var jitterTicks = (long)(JitterFraction(serialNumber) * widthTicks);
        var start = notBefore + TimeSpan.FromTicks(lifetime.Ticks * 2 / 3 + jitterTicks);

        // 2/3 + 2% + one width of jitter tops out around 71% of the lifetime,
        // so this clamp only engages when the minimum width dominates a short
        // lifetime; the window slides back rather than truncating, so the
        // end > start invariant holds by construction. Tick arithmetic rather
        // than start + width, which could overflow DateTimeOffset for a
        // validity ending at the far edge of the representable range.
        var endTicks = Math.Min(start.UtcTicks + widthTicks, notAfter.UtcTicks);
        var end = new DateTimeOffset(endTicks, TimeSpan.Zero);
        if (endTicks == notAfter.UtcTicks)
            start = end - TimeSpan.FromTicks(widthTicks);

        return (start, end);
    }

    /// <summary>
    /// A window entirely before the anchor: whatever instant the client picks
    /// inside it has already gone by, so it renews now. Anchored on a fact
    /// about the certificate rather than the clock, so it is stable across
    /// polls like every other window this class serves.
    /// </summary>
    private static (DateTimeOffset Start, DateTimeOffset End) PastWindowAnchoredOn(
        DateTimeOffset anchor)
    {
        return (anchor - TimeSpan.FromHours(2), anchor - TimeSpan.FromHours(1));
    }

    private static double JitterFraction(ReadOnlySpan<byte> serialNumber)
    {
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(serialNumber, hash);
        return BinaryPrimitives.ReadUInt64BigEndian(hash) / (double)ulong.MaxValue;
    }
}

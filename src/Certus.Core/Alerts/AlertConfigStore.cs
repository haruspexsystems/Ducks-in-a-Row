using Certus.Core.Configuration;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;

namespace Certus.Core.Alerts;

/// <summary>
/// Reads and writes the slice of alert configuration an administrator owns from
/// the dashboard (issue #162). The single place that touches the alert block of
/// the settings overlay, so the read path the card shows and the write path the
/// endpoint takes cannot disagree about where the file is or what is in it.
///
/// <para>
/// This does not decide what may be written; <see cref="AlertConfigPolicy"/>
/// does. It also does not apply anything to the running process: the overlay is
/// registered with reload switched off and every alert consumer snapshots its
/// options at construction, so a save is in force only after a restart. That is
/// the whole reason the endpoint reports <c>restartPending</c> rather than
/// claiming success.
/// </para>
/// </summary>
public sealed class AlertConfigStore
{
    private readonly CertusOptions _certusOptions;

    /// <param name="configuration">
    /// Used once, at construction, to work out which writable keys an
    /// environment variable or command line switch already supplies. That is a
    /// property of how the process was started and cannot change while it runs,
    /// so there is no reason to recompute it per request.
    /// </param>
    public AlertConfigStore(IOptions<CertusOptions> certusOptions, IConfiguration configuration)
    {
        _certusOptions = certusOptions.Value;
        OutrankedKeys = SettingsOverlay.FindOutrankedKeys(
            configuration, AlertOptions.OutrankableKeys);
    }

    /// <summary>
    /// Writable configuration keys a layer above the overlay supplies. Saving
    /// one of these cannot take effect, and the card says so rather than
    /// appearing to have changed something.
    /// </summary>
    public IReadOnlySet<string> OutrankedKeys { get; }

    /// <summary>The overlay file this store reads and writes.</summary>
    public string OverlayPath => SettingsOverlay.ResolvePath(_certusOptions);

    /// <summary>
    /// What the overlay currently says. A corrupt file is reported rather than
    /// thrown, because the card still has something useful to show: the values
    /// in force come from appsettings.json, and saying that is better than an
    /// error page.
    /// </summary>
    public AlertOverlayState Read()
    {
        var saved = SettingsOverlay.TryLoadAlerts(OverlayPath, out var failure);
        return new AlertOverlayState(saved, Unreadable: failure != null);
    }

    /// <summary>
    /// Persist the writable set, leaving every other overlay key untouched.
    ///
    /// <para>
    /// Goes through <c>SettingsOverlay.Mutate</c>, so the read, change and write
    /// happen under the shared lock and cannot interleave with the HTTPS
    /// certificate renewal writing a thumbprint from its background timer. A
    /// corrupt file throws <see cref="System.Text.Json.JsonException"/> out of
    /// here on purpose: rewriting from an empty record would drop the CA
    /// connection string and unconfigure the CA at the next restart, so the
    /// caller has to answer for it rather than this quietly clobbering.
    /// </para>
    ///
    /// <para>
    /// <paramref name="resolvePasswordBlob"/> receives the password blob the
    /// overlay holds at write time and returns the one to store, and it runs
    /// inside the Mutate callback on purpose. Reading the current blob before
    /// the lock and writing the resolution back after it is the lost update
    /// the Mutate doc warns about: two racing saves where only one changes
    /// the password would let the other write its stale snapshot back,
    /// silently reverting the change. There is deliberately no overload
    /// without the resolver, because a whole block save that never considered
    /// the stored password is exactly how it gets wiped.
    /// </para>
    ///
    /// <para>
    /// <paramref name="resolveUsername"/> is the same contract for the other
    /// half of the credential, added by issue #261 when the config endpoint
    /// stopped returning the username. It is not a convenience: with the value
    /// no longer readable, the form cannot post it back, so the only copy that
    /// survives an ordinary save of an unrelated field is the one this callback
    /// reads off the file under the lock.
    /// </para>
    /// </summary>
    public void Save(
        SettingsOverlay.AlertOverlaySettings alerts,
        Func<string?, string?> resolvePasswordBlob,
        Func<string?, string?> resolveUsername) =>
        SettingsOverlay.Mutate(OverlayPath, current => current with
        {
            Alerts = alerts with
            {
                Smtp = (alerts.Smtp ?? new SettingsOverlay.AlertSmtpOverlaySettings()) with
                {
                    PasswordProtected = resolvePasswordBlob(current.Alerts?.Smtp?.PasswordProtected),
                    Username = resolveUsername(current.Alerts?.Smtp?.Username),
                },
            },
        });
}

/// <summary>
/// The overlay's alert block as last read. <paramref name="Saved"/> null with
/// <paramref name="Unreadable"/> false means nothing was ever saved, which is
/// the normal state of a fresh install; null with true means the file exists and
/// could not be parsed.
/// </summary>
public sealed record AlertOverlayState(
    SettingsOverlay.AlertOverlaySettings? Saved,
    bool Unreadable);

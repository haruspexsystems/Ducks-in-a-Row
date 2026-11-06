using System.Text.Json;

namespace Certus.Core.Configuration;

/// <summary>
/// A change to the settings overlay that was refused because the file it would
/// write could not be loaded as configuration (issue #550). In practice that means
/// it would set one configuration key twice: a key the service manages, written by
/// hand in the colon form at the top level (<c>"Certus:HttpsCertificateTemplate"</c>),
/// and the same member inside the <c>Certus</c> section are one key, and the JSON
/// provider refuses a file that sets a key twice, so the next start would fail.
///
/// <para>
/// A <see cref="JsonException"/>, so every caller that already answers an overlay it
/// cannot read answers this too. Its own type so that a caller can tell the refusal
/// apart from a file that is not valid JSON: the message is this class's own text,
/// naming the file and the key, so it is fit to show an administrator, and it is the
/// one overlay failure <see cref="SettingsOverlay.EnsureCanMutate"/> exists to report
/// before a certificate is enrolled (issue #553).
/// </para>
/// </summary>
public sealed class SettingsOverlayConflictException : JsonException
{
    public SettingsOverlayConflictException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

using System.Globalization;

namespace Certus.Core.Acme.Models;

/// <summary>
/// The one home for the RFC 3339 timestamp form ACME responses carry. Always
/// paired with the invariant culture: custom format specifiers read the time
/// separator and the calendar from the culture, so a host whose locale
/// defaults to a non Gregorian calendar (th-TH, ar-SA) would otherwise emit
/// years centuries off and clients would refuse every timestamp.
/// </summary>
public static class AcmeTimestamps
{
    public const string Rfc3339Format = "yyyy-MM-ddTHH:mm:ssZ";

    /// <summary>
    /// Formats a stored UTC instant. The value is not converted: rows store
    /// UTC and the trailing Z is a literal, exactly as every call site did
    /// before this class existed.
    /// </summary>
    public static string Format(DateTime value)
    {
        return value.ToString(Rfc3339Format, CultureInfo.InvariantCulture);
    }

    public static string? Format(DateTime? value)
    {
        return value is { } instant ? Format(instant) : null;
    }

    public static string Format(DateTimeOffset value)
    {
        return value.UtcDateTime.ToString(Rfc3339Format, CultureInfo.InvariantCulture);
    }
}

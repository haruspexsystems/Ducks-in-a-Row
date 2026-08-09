namespace Certus.Core.Data;

/// <summary>
/// Puts a DateTime that arrived from outside onto the UTC wall clock every
/// timestamp in this database is stored as.
/// </summary>
/// <remarks>
/// CertusDbContext.ConfigureConventions states that convention and installs the
/// converter that restores Kind on read. The converter's write side is identity,
/// so SQLite stores whatever wall clock it is handed, and expiry checks run
/// against DateTime.UtcNow. A value that arrives on a local wall clock and is
/// then stored or compared unchanged is wrong by the host's UTC offset.
///
/// How much work this does depends on how the value arrived, and both paths call
/// it:
///
/// A JSON request body is where it is load-bearing. System.Text.Json resolves an
/// offset qualified instant to DateTimeKind.Local, so an admin sending
/// "2026-08-08T17:00:00+05:00" hands the service that instant rendered on the
/// host's clock rather than 12:00 UTC.
///
/// A query string is where it is only a guard. MVC puts
/// DateTimeModelBinderProvider ahead of SimpleTypeModelBinderProvider, so a
/// DateTime parameter never reaches the plain TypeConverter, which would return
/// Local. It binds with DateTimeStyles.AdjustToUniversal and arrives on Kind Utc
/// already. Normalizing regardless keeps the convention pinned at the edge
/// instead of resting on the framework's binder chain.
///
/// Either way an Unspecified value is taken at its word as already UTC, which is
/// what a caller who sends no offset means here: these are instants, and the
/// whole model is UTC.
/// </remarks>
public static class UtcWallClock
{
    /// <summary>
    /// The value on the UTC wall clock, or null when there is no value. See the
    /// overload below for how each kind is treated.
    /// </summary>
    public static DateTime? Normalize(DateTime? value) =>
        value is DateTime moment ? Normalize(moment) : null;

    /// <summary>
    /// The value on the UTC wall clock. A Local value is converted, which
    /// preserves the instant and changes only how it is expressed. A Utc value
    /// passes through. An Unspecified value is relabelled without moving.
    /// </summary>
    public static DateTime Normalize(DateTime value) => value.Kind switch
    {
        DateTimeKind.Local => value.ToUniversalTime(),
        DateTimeKind.Utc => value,
        _ => DateTime.SpecifyKind(value, DateTimeKind.Utc),
    };
}

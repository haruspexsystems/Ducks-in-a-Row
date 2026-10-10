namespace Certus.Core.Acme.Services;

/// <summary>
/// Configuration for the sweep that resolves orders the CA is holding for
/// manager approval. Stored in the "Certus:Acme:PendingIssuance" configuration
/// section.
/// </summary>
/// <remarks>
/// Deliberately absent from appsettings.json. Every key that ships there as an
/// explicit JSON null has its C# initializer overwritten by the configuration
/// binder, so an option that looks like it defaults to a value is null at
/// runtime (see CertusOptions.NormalizeDatabasePath and PR #86). Leaving this
/// section out of the file entirely means the initializer below is the default,
/// with no post configure step needed to defend it.
/// </remarks>
public sealed class PendingIssuanceOptions
{
    public const string SectionName = "Certus:Acme:PendingIssuance";

    /// <summary>
    /// How often the background worker sweeps for orders in "processing" state,
    /// in seconds. Defaults to 60.
    /// <para>
    /// The thing being waited on is a human opening the CA console, so this is
    /// deliberately far slower than the challenge worker's five seconds: each
    /// tick costs one CA round trip per held order, and shortening the interval
    /// buys nothing against a wait measured in minutes to days. It is fast
    /// enough that an operator who approves while the client is still polling
    /// sees the certificate delivered on that same client run.
    /// </para>
    /// <para>
    /// The worker clamps the value to between 5 seconds and an hour, so a bad
    /// value can neither spin the CA nor stall issuance for good. The tests
    /// shrink it so a sweep completes without dead waiting.
    /// </para>
    /// </summary>
    public double PollIntervalSeconds { get; set; } = 60;
}

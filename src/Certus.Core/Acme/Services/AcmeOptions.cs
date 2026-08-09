namespace Certus.Core.Acme.Services;

/// <summary>
/// Configuration for the ACME surface as a whole. Stored in the "Certus:Acme"
/// configuration section. Narrower concerns nest below it, for example
/// <see cref="ChallengeValidationOptions"/> at "Certus:Acme:ChallengeValidation".
/// </summary>
public sealed class AcmeOptions
{
    public const string SectionName = "Certus:Acme";

    /// <summary>
    /// Break-glass override: expose every CA published template over ACME even
    /// when the wizard status file records no enabled template set, and ignore
    /// the recorded set when one exists. Defaults to false: with no set
    /// recorded, no template is exposed (issue #101). Setting this to true is
    /// a deliberate, visible choice that is named in a startup warning; it is
    /// not written by the wizard and ships in no appsettings file.
    /// </summary>
    public bool ExposeAllTemplates { get; set; }
}

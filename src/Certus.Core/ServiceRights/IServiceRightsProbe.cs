namespace Certus.Core.ServiceRights;

/// <summary>
/// The readings behind the service rights check that only Windows can take
/// (issue #440): whether the ADCS COM classes are present, which account the
/// service is on the network and which groups it carries, what the CA says the
/// service may do, and what each template's permission list says.
///
/// A separate interface rather than members on
/// <see cref="Certus.Core.Adcs.IAdcsClient"/>, for the reason
/// <see cref="Certus.Core.Crl.ICaCrlReader"/> gives: that one has a dozen
/// implementations, most of them test doubles for unrelated paths. This one has
/// exactly two, the real reader in Certus.Adcs and the mock the dev host runs.
///
/// Every member returns an outcome and never throws, except when the caller
/// cancels. The signatures carry plain types (SID strings, masks, GUIDs) so that
/// nothing Windows specific leaks into Certus.Core.
///
/// Every reading is taken as the service's own identity and never under
/// impersonation of the administrator driving the wizard. The whole point is to
/// prove the service's rights; the administrator's are the wrong answer.
/// </summary>
public interface IServiceRightsProbe
{
    /// <summary>
    /// True only for the dev host's simulated probe, so a report can say its
    /// answers are made up rather than let them pass for a real CA's.
    /// </summary>
    bool Simulated { get; }

    /// <summary>
    /// Activates CertRequest, CertView and CertAdmin on this server. Local only;
    /// nothing reaches the CA.
    /// </summary>
    Task<ComponentsReading> CheckComponentsAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Reads whether this server is domain joined, which account the service
    /// reaches the network as, and that account's groups.
    /// </summary>
    Task<PrincipalReading> ReadServicePrincipalAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Asks the CA which roles it grants the service (<c>ICertAdmin2::GetMyRoles</c>).
    /// Read only; it changes nothing on the CA.
    /// </summary>
    Task<CaRolesReading> ReadCaRolesAsync(
        string caConnectionString,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Reads one template's permission list from the directory, as the service's account.
    /// </summary>
    /// <param name="templateName">The template's programmatic name (its <c>cn</c>).</param>
    /// <param name="cancellationToken">Cancels the wait, not a directory call already in flight.</param>
    Task<TemplateDaclReading> ReadTemplateDaclAsync(
        string templateName,
        CancellationToken cancellationToken = default);
}

namespace Certus.Core.ServiceRights;

/// <summary>
/// The dev host's <see cref="IServiceRightsProbe"/>, and the double the tests
/// set up (issue #440). It answers for an example estate, not for the machine it
/// runs on.
///
/// The identity is fixed rather than read from this process on purpose. The
/// documentation screenshots are captured on the dev host, which runs as the
/// developer, and no test scans images for a leaked account name, so the only
/// safe answer is one that was never real. The defaults describe a typical
/// pilot: the CA grants Read and Request Certificates but not Issue and Manage
/// Certificates, and every template grants Enroll through Authenticated Users.
/// </summary>
public sealed class MockServiceRightsProbe : IServiceRightsProbe
{
    /// <summary>The example computer account's SID. The domain part is made up.</summary>
    public const string ExampleAccountSid = "S-1-5-21-1004336348-1177238915-682003330-1105";

    /// <summary>The example domain's Domain Computers group, the computer account's primary group.</summary>
    public const string ExampleDomainComputersSid = "S-1-5-21-1004336348-1177238915-682003330-515";

    public bool Simulated => true;

    /// <summary>What <see cref="CheckComponentsAsync"/> answers.</summary>
    public ComponentsReading Components { get; set; } = new(
    [
        new ComponentReading("CertRequest", ReadingOutcome.Ok),
        new ComponentReading("CertView", ReadingOutcome.Ok),
        new ComponentReading("CertAdmin", ReadingOutcome.Ok),
    ]);

    /// <summary>What <see cref="ReadServicePrincipalAsync"/> answers.</summary>
    public PrincipalReading Principal { get; set; } = new(
        ReadingOutcome.Ok,
        DomainJoined: true,
        DomainName: "CORP",
        ProcessIdentity: @"NT AUTHORITY\SYSTEM",
        IsMachineIdentity: true,
        AccountName: @"CORP\DUCKS01$",
        AccountSid: ExampleAccountSid,
        GroupSids: [ExampleDomainComputersSid]);

    /// <summary>What <see cref="ReadCaRolesAsync"/> answers, whatever CA is asked.</summary>
    public CaRolesReading Roles { get; set; } =
        new(ReadingOutcome.Ok, CaAccessRoles.Read | CaAccessRoles.Enroll);

    /// <summary>
    /// What <see cref="ReadTemplateDaclAsync"/> answers for a template name.
    /// Defaults to Enroll granted through Authenticated Users, which is how a
    /// stock template is usually shared.
    /// </summary>
    public Func<string, TemplateDaclReading> TemplateDacl { get; set; } = name => new TemplateDaclReading(
        name,
        ReadingOutcome.Ok,
        [
            new AclEntry(
                AclEntryKind.Allow,
                TemplateEnrollEvaluator.ControlAccess,
                TemplateEnrollEvaluator.EnrollRight,
                InheritOnly: false,
                Inherited: false,
                TemplateEnrollEvaluator.AuthenticatedUsersSid),
        ],
        Sddl: "D:(OA;;CR;0e10c968-78fb-11d2-90d4-00c04f79dc55;;AU)");

    public Task<ComponentsReading> CheckComponentsAsync(CancellationToken cancellationToken = default)
        => Task.FromResult(Components);

    public Task<PrincipalReading> ReadServicePrincipalAsync(CancellationToken cancellationToken = default)
        => Task.FromResult(Principal);

    public Task<CaRolesReading> ReadCaRolesAsync(
        string caConnectionString,
        CancellationToken cancellationToken = default)
        => Task.FromResult(Roles);

    public Task<TemplateDaclReading> ReadTemplateDaclAsync(
        string templateName,
        CancellationToken cancellationToken = default)
        => Task.FromResult(TemplateDacl(templateName));
}

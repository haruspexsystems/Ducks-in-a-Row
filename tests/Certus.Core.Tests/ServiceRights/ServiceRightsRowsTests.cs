using Certus.Core.ServiceRights;

namespace Certus.Core.Tests.ServiceRights;

/// <summary>
/// The row builders of the service rights check, issue #440. Each test moves one
/// observation away from a check where everything answered, and pins what the
/// row may then claim. The rules they defend: Inferred is never a pass, evidence
/// never overrides a Failed row, a refusal of Test Connection does not skip the
/// rows that could still answer, and a row claims only what was measured.
/// </summary>
public class ServiceRightsRowsTests
{
    private const string Account = "S-1-5-21-1004336348-1177238915-682003330-1105";
    private const string DomainComputers = "S-1-5-21-1004336348-1177238915-682003330-515";
    private const string AccountName = @"CORP\DUCKS01$";

    private static readonly ServiceRightsFindings Measured = ServiceRightsFindings.MeasuredOnLab2019;

    private static TemplateDaclReading Dacl(params AclEntry[] entries) =>
        new("WebServerACME", ReadingOutcome.Ok, entries);

    private static AclEntry EnrollFor(string sid, AclEntryKind kind = AclEntryKind.Allow) =>
        new(kind, TemplateEnrollEvaluator.ControlAccess, TemplateEnrollEvaluator.EnrollRight, false, false, sid);

    private static ServiceRightsObservations AllAnswered() => new(
        new ComponentsReading(
        [
            new ComponentReading("CertRequest", ReadingOutcome.Ok),
            new ComponentReading("CertView", ReadingOutcome.Ok),
            new ComponentReading("CertAdmin", ReadingOutcome.Ok),
        ]),
        new PrincipalReading(ReadingOutcome.Ok, true, "CORP", @"NT AUTHORITY\SYSTEM", true, AccountName, Account, [DomainComputers]),
        new CaCallObservation(CaCallOutcome.Answered),
        new CaRolesReading(ReadingOutcome.Ok, CaAccessRoles.Officer | CaAccessRoles.Read | CaAccessRoles.Enroll),
        new CaCallObservation(CaCallOutcome.Answered),
        [new TemplateObservation("WebServerACME", "Web Server ACME", true, Dacl(EnrollFor(TemplateEnrollEvaluator.AuthenticatedUsersSid)))],
        Evidence: null,
        Simulated: false);

    private static ServiceRightsRow Row(IReadOnlyList<ServiceRightsRow> rows, string id) =>
        rows.Single(r => r.Id == id);

    [Fact]
    public void EverythingAnswered_ProvesWhatWasExercised_AndInfersTheRest()
    {
        var rows = ServiceRightsRows.Build(AllAnswered(), Measured);

        rows.Select(r => r.Id).Should().Equal(
            "domain", "components", "ca-connect", "ca-enroll", "ca-read", "ca-officer",
            "template:WebServerACME", "https-enrolment", "challenge-egress");

        Row(rows, "domain").Status.Should().Be(RightsStatus.Proven);
        Row(rows, "components").Status.Should().Be(RightsStatus.Proven);
        Row(rows, "ca-connect").Status.Should().Be(RightsStatus.Proven);
        Row(rows, "ca-enroll").Should().Match<ServiceRightsRow>(r =>
            r.Status == RightsStatus.Proven && r.Basis == RightsBasis.Exercised);
        Row(rows, "ca-read").Should().Match<ServiceRightsRow>(r =>
            r.Status == RightsStatus.Proven && r.Basis == RightsBasis.Exercised);
        Row(rows, "ca-officer").Should().Match<ServiceRightsRow>(r =>
            r.Status == RightsStatus.Inferred && r.Basis == RightsBasis.ReportedByCa && r.Optional);
        Row(rows, "template:WebServerACME").Should().Match<ServiceRightsRow>(r =>
            r.Status == RightsStatus.Inferred && r.Basis == RightsBasis.ReadFromAcl && r.Template == "WebServerACME");
        Row(rows, "https-enrolment").Status.Should().Be(RightsStatus.Unproven);
        Row(rows, "challenge-egress").Status.Should().Be(RightsStatus.Unproven);
    }

    [Fact]
    public void AReadingIsNeverAPass()
    {
        // The two readings in a healthy check: the CA's report of Issue and
        // Manage, and a template's permission list. Neither may read Proven.
        var rows = ServiceRightsRows.Build(AllAnswered(), Measured);

        rows.Where(r => r.Basis is RightsBasis.ReportedByCa or RightsBasis.ReadFromAcl)
            .Should().NotBeEmpty()
            .And.OnlyContain(r => r.Status != RightsStatus.Proven);
    }

    [Fact]
    public void TestConnectionRefused_FailsRequestCertificates_ButStillAsksTheRest()
    {
        var observations = AllAnswered() with
        {
            Connect = new CaCallObservation(CaCallOutcome.AccessDenied, "the connect message"),
            Roles = new CaRolesReading(ReadingOutcome.Ok, CaAccessRoles.Read),
        };

        var rows = ServiceRightsRows.Build(observations, Measured);

        Row(rows, "ca-connect").Should().Match<ServiceRightsRow>(r =>
            r.Status == RightsStatus.Failed && r.Remedy == "the connect message");
        Row(rows, "ca-enroll").Should().Match<ServiceRightsRow>(r =>
            r.Status == RightsStatus.Failed && r.Basis == RightsBasis.Exercised);
        // Read without Request Certificates is a real state (the lab's S2): the
        // view and the role report still answer, so they are not skipped.
        Row(rows, "ca-read").Status.Should().Be(RightsStatus.Proven);
        Row(rows, "ca-officer").Status.Should().Be(RightsStatus.Failed);
    }

    [Theory]
    [InlineData(CaCallOutcome.Unavailable)]
    [InlineData(CaCallOutcome.ComponentsMissing)]
    [InlineData(CaCallOutcome.TimedOut)]
    public void ACaThatCannotBeReached_SkipsTheRowsThatNeedIt(CaCallOutcome outcome)
    {
        var observations = AllAnswered() with
        {
            Connect = new CaCallObservation(outcome),
            Roles = null,
            View = CaCallObservation.NotAttempted,
        };

        var rows = ServiceRightsRows.Build(observations, Measured);

        Row(rows, "ca-enroll").Status.Should().Be(RightsStatus.Skipped);
        Row(rows, "ca-read").Status.Should().Be(RightsStatus.Skipped);
        Row(rows, "ca-officer").Status.Should().Be(RightsStatus.Skipped);
    }

    [Fact]
    public void ACaThatDidNotAnswerInTime_IsUnproven_NotFailed()
    {
        var rows = ServiceRightsRows.Build(
            AllAnswered() with { Connect = new CaCallObservation(CaCallOutcome.TimedOut), View = CaCallObservation.NotAttempted },
            Measured);

        Row(rows, "ca-connect").Status.Should().Be(RightsStatus.Unproven);
    }

    [Fact]
    public void WhenTestConnectionProvesNothing_RequestCertificatesComesFromTheCaReport()
    {
        var unmeasured = Measured with { ConnectProvesRequestCertificates = false };

        ServiceRightsRows.Build(AllAnswered(), unmeasured).Single(r => r.Id == "ca-enroll")
            .Should().Match<ServiceRightsRow>(r => r.Status == RightsStatus.Inferred && r.Basis == RightsBasis.ReportedByCa);

        ServiceRightsRows.Build(AllAnswered() with { Roles = new CaRolesReading(ReadingOutcome.Ok, CaAccessRoles.Read) }, unmeasured)
            .Single(r => r.Id == "ca-enroll").Status.Should().Be(RightsStatus.Failed);
    }

    [Fact]
    public void ARoleReportThatWasNotMeasured_IsNotReliedOn()
    {
        var rows = ServiceRightsRows.Build(AllAnswered(), Measured with { CaRolesTrusted = false });

        Row(rows, "ca-officer").Status.Should().Be(RightsStatus.Unproven);
    }

    [Fact]
    public void ARefusedRoleReport_LeavesIssueAndManageUnproven_AndSaysGrantRead()
    {
        var rows = ServiceRightsRows.Build(
            AllAnswered() with { Roles = new CaRolesReading(ReadingOutcome.AccessDenied, null) }, Measured);

        Row(rows, "ca-officer").Should().Match<ServiceRightsRow>(r =>
            r.Status == RightsStatus.Unproven && r.Detail.Contains("grant Read"));
        // Request Certificates rests on Test Connection, not on the report.
        Row(rows, "ca-enroll").Status.Should().Be(RightsStatus.Proven);
    }

    [Fact]
    public void AMissingOfficerRole_FailsTheOptionalRow_AndSaysRevocationOnly()
    {
        var rows = ServiceRightsRows.Build(
            AllAnswered() with { Roles = new CaRolesReading(ReadingOutcome.Ok, CaAccessRoles.Read | CaAccessRoles.Enroll) }, Measured);

        Row(rows, "ca-officer").Should().Match<ServiceRightsRow>(r =>
            r.Status == RightsStatus.Failed && r.Optional && r.NeededFor == RightNeededFor.Revocation);
    }

    [Fact]
    public void ARefusedView_FailsTheInventory_AndNamesRead()
    {
        var rows = ServiceRightsRows.Build(
            AllAnswered() with
            {
                View = new CaCallObservation(CaCallOutcome.AccessDenied),
                Roles = new CaRolesReading(ReadingOutcome.AccessDenied, null),
            },
            Measured);

        Row(rows, "ca-read").Should().Match<ServiceRightsRow>(r =>
            r.Status == RightsStatus.Failed && r.Remedy!.Contains("Read on the CA") && r.Detail.Contains("Request Certificates alone"));
    }

    [Fact]
    public void ARefusedView_WhileTheCaReportsRead_PointsAtTheInterfaceFlag()
    {
        var rows = ServiceRightsRows.Build(
            AllAnswered() with
            {
                View = new CaCallObservation(CaCallOutcome.AccessDenied),
                Roles = new CaRolesReading(ReadingOutcome.Ok, CaAccessRoles.Read),
            },
            Measured);

        Row(rows, "ca-read").Detail.Should().Contain("IF_NOREMOTEICERTADMIN");
    }

    [Fact]
    public void AViewThatOpensWithoutProofOfCompleteness_IsInferred_AndIssueAndManageBecomesAnInventoryRight()
    {
        var rows = ServiceRightsRows.Build(AllAnswered(), Measured with { ViewOpenProvesInventory = false });

        Row(rows, "ca-read").Status.Should().Be(RightsStatus.Inferred);
        Row(rows, "ca-officer").NeededFor.Should().HaveFlag(RightNeededFor.Inventory);
    }

    [Fact]
    public void ATemplateDenyForTheAccount_Fails_NamingTheAccount()
    {
        var observations = AllAnswered() with
        {
            Templates =
            [
                new TemplateObservation("WebServerACME", "Web Server ACME", true,
                    Dacl(EnrollFor(Account, AclEntryKind.Deny), EnrollFor(TemplateEnrollEvaluator.AuthenticatedUsersSid))),
            ],
        };

        var row = ServiceRightsRows.Build(observations, Measured).Single(r => r.Id == "template:WebServerACME");

        row.Status.Should().Be(RightsStatus.Failed);
        row.Detail.Should().Contain(AccountName);
    }

    [Fact]
    public void ATemplateWithNoGrant_Fails_WithTheOtherDomainCaveat()
    {
        var observations = AllAnswered() with
        {
            Templates = [new TemplateObservation("WebServer", "Web Server", true, Dacl())],
        };

        var row = ServiceRightsRows.Build(observations, Measured).Single(r => r.Id == "template:WebServer");

        row.Status.Should().Be(RightsStatus.Failed);
        row.Detail.Should().Contain("another domain");
        row.Remedy.Should().Contain("Grant Enroll");
    }

    [Fact]
    public void ATemplateGrantThroughDomainComputers_IsNamedSo()
    {
        var observations = AllAnswered() with
        {
            Templates = [new TemplateObservation("WebServerACME", "Web Server ACME", true, Dacl(EnrollFor(DomainComputers)))],
        };

        ServiceRightsRows.Build(observations, Measured).Single(r => r.Id == "template:WebServerACME")
            .Detail.Should().Contain("Domain Computers");
    }

    [Fact]
    public void AutoenrollHeldToo_IsCalledOverGranted()
    {
        var autoenroll = new AclEntry(AclEntryKind.Allow, TemplateEnrollEvaluator.ControlAccess,
            TemplateEnrollEvaluator.AutoenrollRight, false, false, TemplateEnrollEvaluator.AuthenticatedUsersSid);
        var observations = AllAnswered() with
        {
            Templates =
            [
                new TemplateObservation("WebServerACME", "Web Server ACME", true,
                    Dacl(EnrollFor(TemplateEnrollEvaluator.AuthenticatedUsersSid), autoenroll)),
            ],
        };

        ServiceRightsRows.Build(observations, Measured).Single(r => r.Id == "template:WebServerACME")
            .Detail.Should().Contain("Autoenroll");
    }

    [Fact]
    public void AnUnpublishedTemplate_Fails_WithoutReadingItsPermissions()
    {
        var observations = AllAnswered() with
        {
            Templates = [new TemplateObservation("Gone", "Gone", false, null)],
        };

        ServiceRightsRows.Build(observations, Measured).Single(r => r.Id == "template:Gone")
            .Should().Match<ServiceRightsRow>(r => r.Status == RightsStatus.Failed && r.Basis == RightsBasis.Local);
    }

    [Fact]
    public void ATemplate_WhenTheAccountCouldNotBeRead_IsSkipped()
    {
        var observations = AllAnswered() with
        {
            Principal = new PrincipalReading(ReadingOutcome.Unavailable, true, "CORP", @"NT AUTHORITY\SYSTEM", true, null, null, []),
        };

        ServiceRightsRows.Build(observations, Measured).Single(r => r.Id == "template:WebServerACME")
            .Status.Should().Be(RightsStatus.Skipped);
    }

    [Theory]
    [InlineData(ReadingOutcome.AccessDenied, RightsStatus.Unproven)]
    [InlineData(ReadingOutcome.Unavailable, RightsStatus.Unproven)]
    // Not Failed: a search that ran out of time also comes back empty, and here
    // the CA has just said it publishes the template.
    [InlineData(ReadingOutcome.NotFound, RightsStatus.Unproven)]
    public void ATemplateWhosePermissionsWereNotRead_SaysWhy(ReadingOutcome outcome, RightsStatus expected)
    {
        var observations = AllAnswered() with
        {
            Templates = [new TemplateObservation("WebServerACME", "Web Server ACME", true, new TemplateDaclReading("WebServerACME", outcome, [], Detail: "why"))],
        };

        ServiceRightsRows.Build(observations, Measured).Single(r => r.Id == "template:WebServerACME")
            .Should().Match<ServiceRightsRow>(r => r.Status == expected && r.Detail == "why");
    }

    [Fact]
    public void ATemplateReadThatTimedOut_IsUnproven()
    {
        var observations = AllAnswered() with
        {
            Templates = [new TemplateObservation("WebServerACME", "Web Server ACME", true, null, DaclTimedOut: true)],
        };

        ServiceRightsRows.Build(observations, Measured).Single(r => r.Id == "template:WebServerACME")
            .Should().Match<ServiceRightsRow>(r => r.Status == RightsStatus.Unproven && r.Detail.Contains("20 seconds"));
    }

    [Fact]
    public void Evidence_ProvesItsOwnTemplate_AndNoOther()
    {
        var observations = AllAnswered() with
        {
            Templates =
            [
                new TemplateObservation("WebServerACME", "Web Server ACME", true, Dacl(EnrollFor(TemplateEnrollEvaluator.AuthenticatedUsersSid))),
                new TemplateObservation("Other", "Other", true, Dacl(EnrollFor(TemplateEnrollEvaluator.AuthenticatedUsersSid))),
            ],
            Evidence = new EnrollmentEvidence("webserveracme", new DateTimeOffset(2026, 9, 20, 10, 0, 0, TimeSpan.Zero)),
        };

        var rows = ServiceRightsRows.Build(observations, Measured);

        Row(rows, "template:WebServerACME").Should().Match<ServiceRightsRow>(r =>
            r.Status == RightsStatus.Proven && r.Basis == RightsBasis.PriorEnrollment && r.Detail.Contains("2026-09-20"));
        Row(rows, "template:Other").Status.Should().Be(RightsStatus.Inferred);
        Row(rows, "https-enrolment").Status.Should().Be(RightsStatus.Proven);
    }

    [Fact]
    public void Evidence_NeverOverridesAFailure()
    {
        // A current refusal outranks an old success: the certificate was issued
        // before someone removed the grant.
        var observations = AllAnswered() with
        {
            Templates = [new TemplateObservation("WebServerACME", "Web Server ACME", true, Dacl(EnrollFor(Account, AclEntryKind.Deny)))],
            Evidence = new EnrollmentEvidence("WebServerACME", DateTimeOffset.UtcNow),
        };

        ServiceRightsRows.Build(observations, Measured).Single(r => r.Id == "template:WebServerACME")
            .Status.Should().Be(RightsStatus.Failed);
    }

    [Fact]
    public void Evidence_UpgradesAReportedRequestCertificates()
    {
        var observations = AllAnswered() with
        {
            Evidence = new EnrollmentEvidence("WebServerACME", DateTimeOffset.UtcNow),
        };

        ServiceRightsRows.Build(observations, Measured with { ConnectProvesRequestCertificates = false })
            .Single(r => r.Id == "ca-enroll")
            .Should().Match<ServiceRightsRow>(r => r.Status == RightsStatus.Proven && r.Basis == RightsBasis.PriorEnrollment);
    }

    [Fact]
    public void Evidence_NeverOverridesARequestCertificatesTheCaDenies()
    {
        // The same rule on the CA's row. Under the lab's findings this path is
        // unreachable, because evidence needs a Test Connection that answered and
        // that answer already proves the row, so it is pinned under the others.
        var observations = AllAnswered() with
        {
            Roles = new CaRolesReading(ReadingOutcome.Ok, CaAccessRoles.Read),
            Evidence = new EnrollmentEvidence("WebServerACME", DateTimeOffset.UtcNow),
        };

        ServiceRightsRows.Build(observations, Measured with { ConnectProvesRequestCertificates = false })
            .Single(r => r.Id == "ca-enroll").Status.Should().Be(RightsStatus.Failed);
    }

    [Fact]
    public void OnTheDemoCa_TheEnrolmentRowIsSkipped()
    {
        ServiceRightsRows.Build(AllAnswered() with { Simulated = true }, Measured)
            .Single(r => r.Id == "https-enrolment").Status.Should().Be(RightsStatus.Skipped);
    }

    [Fact]
    public void AServerOutsideADomain_FailsMembership_WithTheRemedy()
    {
        var rows = ServiceRightsRows.Build(
            AllAnswered() with
            {
                Principal = new PrincipalReading(ReadingOutcome.NotDomainJoined, false, "WORKGROUP", @"NT AUTHORITY\SYSTEM", true, null, null, []),
            },
            Measured);

        Row(rows, "domain").Should().Match<ServiceRightsRow>(r =>
            r.Status == RightsStatus.Failed && r.Remedy!.Contains("Join this server"));
    }

    [Fact]
    public void AnUnreadJoinState_IsUnproven()
    {
        ServiceRightsRows.Domain(null).Status.Should().Be(RightsStatus.Unproven);
        ServiceRightsRows.Domain(new PrincipalReading(ReadingOutcome.Failed, null, null, "x", false, null, null, []))
            .Status.Should().Be(RightsStatus.Unproven);
    }

    [Fact]
    public void AMissingComponent_FailsTheRow_NamingWhatItServes()
    {
        var row = ServiceRightsRows.Components(new ComponentsReading(
        [
            new ComponentReading("CertRequest", ReadingOutcome.Ok),
            new ComponentReading("CertView", ReadingOutcome.NotRegistered, unchecked((int)0x80040154)),
            new ComponentReading("CertAdmin", ReadingOutcome.Ok),
        ]));

        row.Status.Should().Be(RightsStatus.Failed);
        row.Detail.Should().Contain("CertView").And.Contain("the certificate inventory");
        row.Remedy.Should().Contain("RSAT-ADCS-Mgmt");
    }

    [Fact]
    public void EveryRow_SaysWhatItIsNeededFor()
    {
        ServiceRightsRows.Build(AllAnswered(), Measured)
            .Should().OnlyContain(r => r.NeededFor != RightNeededFor.None);
    }
}

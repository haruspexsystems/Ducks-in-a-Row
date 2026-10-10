using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certus.Core.Adcs;
using Certus.Core.Configuration;
using Certus.Core.ServiceRights;
using Certus.Core.Setup;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;

namespace Certus.Core.Tests.ServiceRights;

/// <summary>
/// The orchestration of the service rights check, issue #440: which calls it
/// makes, which it skips, how a deadline turns a hung reading into Unproven,
/// and what counts as evidence of an earlier enrolment.
/// </summary>
public class ServiceRightsCheckTests : IDisposable
{
    private const string Ca = @"ca.example.com\Example CA";
    private const string Account = "S-1-5-21-1004336348-1177238915-682003330-1105";

    private readonly string _tempDir;
    private readonly IAdcsClient _client = Substitute.For<IAdcsClient>();
    private readonly IAdcsClientFactory _factory = Substitute.For<IAdcsClientFactory>();
    private readonly IServiceRightsProbe _probe = Substitute.For<IServiceRightsProbe>();
    private readonly IHttpsCertificateStore _store = Substitute.For<IHttpsCertificateStore>();
    private readonly CertusOptions _options;

    public ServiceRightsCheckTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"certus-rights-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
        _options = new CertusOptions
        {
            DatabasePath = Path.Combine(_tempDir, "certus.db"),
            SettingsOverlayPath = Path.Combine(_tempDir, "settings.json"),
        };

        _factory.Create(Arg.Any<string>()).Returns(_client);
        _client.GetCaInfoAsync(Arg.Any<CancellationToken>()).Returns(new CaInfo("Example CA", "ca.example.com", "Example CA", true));
        _client.GetRequestStatusAsync(Arg.Any<int>(), Arg.Any<CancellationToken>()).Returns((CaRequestStatus?)null);
        _client.GetTemplatesAsync(Arg.Any<CancellationToken>()).Returns(new List<TemplateInfo>
        {
            new("WebServerACME", "Web Server ACME", "1.2.3"),
        });

        _probe.Simulated.Returns(false);
        _probe.CheckComponentsAsync(Arg.Any<CancellationToken>()).Returns(new ComponentsReading(
            [new ComponentReading("CertRequest", ReadingOutcome.Ok), new ComponentReading("CertView", ReadingOutcome.Ok), new ComponentReading("CertAdmin", ReadingOutcome.Ok)]));
        _probe.ReadServicePrincipalAsync(Arg.Any<CancellationToken>()).Returns(new PrincipalReading(
            ReadingOutcome.Ok, true, "CORP", @"NT AUTHORITY\SYSTEM", true, @"CORP\DUCKS01$", Account, []));
        _probe.ReadCaRolesAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new CaRolesReading(ReadingOutcome.Ok, CaAccessRoles.Read | CaAccessRoles.Enroll));
        _probe.ReadTemplateDaclAsync(Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(call => new TemplateDaclReading(
            call.Arg<string>(), ReadingOutcome.Ok,
            [new AclEntry(AclEntryKind.Allow, TemplateEnrollEvaluator.ControlAccess, TemplateEnrollEvaluator.EnrollRight, false, false, TemplateEnrollEvaluator.AuthenticatedUsersSid)]));
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch (IOException) { }
    }

    private ServiceRightsCheck Create(Func<TimeSpan, CancellationToken, Task>? delay = null) => new(
        _factory, _probe, _store, Options.Create(_options), NullLogger<ServiceRightsCheck>.Instance,
        delay ?? ((limit, ct) => Task.Delay(limit, ct)),
        ServiceRightsFindings.MeasuredOnLab2019);

    private static ServiceRightsRow Row(ServiceRightsReport report, string id) => report.Rows.Single(r => r.Id == id);

    [Fact]
    public async Task AHealthyCheck_ReportsTheAccountAndEveryRow()
    {
        var report = await Create().RunAsync(Ca, ["WebServerACME"]);

        report.CaConnectionString.Should().Be(Ca);
        report.Identity.AccountName.Should().Be(@"CORP\DUCKS01$");
        report.Identity.IsMachineIdentity.Should().BeTrue();
        report.Simulated.Should().BeFalse();
        Row(report, "ca-enroll").Status.Should().Be(RightsStatus.Proven);
        Row(report, "ca-read").Status.Should().Be(RightsStatus.Proven);
        Row(report, "template:WebServerACME").Status.Should().Be(RightsStatus.Inferred);
    }

    [Fact]
    public async Task TheCheckRunsAgainstTheCandidateCa_NotTheConfiguredOne()
    {
        await Create().RunAsync(Ca, []);

        _factory.Received(1).Create(Ca);
        await _probe.Received(1).ReadCaRolesAsync(Ca, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task TheViewIsReadByAnIdNoCaWillHaveReached()
    {
        await Create().RunAsync(Ca, []);

        await _client.Received(1).GetRequestStatusAsync(int.MaxValue, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ARefusedTestConnection_StillAsksForTheViewAndTheRoles()
    {
        _client.GetCaInfoAsync(Arg.Any<CancellationToken>()).Returns<CaInfo>(_ =>
            throw new CaAccessDeniedException(CaAccessDeniedException.ConnectPermissionMessage, new UnauthorizedAccessException()));

        var report = await Create().RunAsync(Ca, []);

        Row(report, "ca-connect").Status.Should().Be(RightsStatus.Failed);
        Row(report, "ca-connect").Remedy.Should().Be(CaAccessDeniedException.ConnectPermissionMessage);
        await _client.Received(1).GetRequestStatusAsync(int.MaxValue, Arg.Any<CancellationToken>());
        await _probe.Received(1).ReadCaRolesAsync(Ca, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task AnUnreachableCa_IsNotAskedAnythingElse()
    {
        _client.GetCaInfoAsync(Arg.Any<CancellationToken>()).Returns<CaInfo>(_ => throw new CaUnavailableException("down"));

        var report = await Create().RunAsync(Ca, ["WebServerACME"]);

        Row(report, "ca-connect").Status.Should().Be(RightsStatus.Failed);
        Row(report, "ca-read").Status.Should().Be(RightsStatus.Skipped);
        await _client.DidNotReceive().GetRequestStatusAsync(Arg.Any<int>(), Arg.Any<CancellationToken>());
        await _probe.DidNotReceive().ReadCaRolesAsync(Arg.Any<string>(), Arg.Any<CancellationToken>());
        await _client.DidNotReceive().GetTemplatesAsync(Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ARefusedView_FailsTheInventoryRow()
    {
        _client.GetRequestStatusAsync(Arg.Any<int>(), Arg.Any<CancellationToken>()).Returns<CaRequestStatus?>(_ =>
            throw new CaAccessDeniedException(CaAccessDeniedException.SyncReadPermissionMessage, new UnauthorizedAccessException()));

        var report = await Create().RunAsync(Ca, []);

        Row(report, "ca-read").Status.Should().Be(RightsStatus.Failed);
    }

    [Fact]
    public async Task AReadingPastItsDeadline_IsUnproven_AndDoesNotHoldTheReport()
    {
        // The CA never answers, and the deadline has already passed. Without the
        // deadline this would wait for ever, so the wait is bounded: a regression
        // reports rather than hangs the run.
        _client.GetCaInfoAsync(Arg.Any<CancellationToken>()).Returns(new TaskCompletionSource<CaInfo>().Task);

        var report = await Bounded(Create(delay: (_, _) => Task.CompletedTask).RunAsync(Ca, []));

        Row(report, "ca-connect").Status.Should().Be(RightsStatus.Unproven);
        Row(report, "ca-connect").Detail.Should().Contain("did not answer");
        Row(report, "ca-read").Status.Should().Be(RightsStatus.Skipped);
    }

    [Fact]
    public async Task ACallerThatCancels_GetsAnException_NotAReportOfUnprovenRows()
    {
        _client.GetCaInfoAsync(Arg.Any<CancellationToken>()).Returns(new TaskCompletionSource<CaInfo>().Task);
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var run = () => Bounded(Create(delay: (_, ct) => Task.Delay(Timeout.InfiniteTimeSpan, ct)).RunAsync(Ca, [], cts.Token));

        await run.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task AProbeThatBreaksItsContract_CostsOneRow_NotTheReport()
    {
        _probe.ReadServicePrincipalAsync(Arg.Any<CancellationToken>())
            .Returns<PrincipalReading>(_ => throw new InvalidOperationException("broken"));

        var report = await Create().RunAsync(Ca, ["WebServerACME"]);

        Row(report, "domain").Status.Should().Be(RightsStatus.Unproven);
        Row(report, "template:WebServerACME").Status.Should().Be(RightsStatus.Skipped);
        Row(report, "ca-read").Status.Should().Be(RightsStatus.Proven);
    }

    [Fact]
    public async Task ATemplateNamedByItsDisplayName_IsReadByItsProgrammaticName()
    {
        var report = await Create().RunAsync(Ca, ["Web Server ACME"]);

        await _probe.Received(1).ReadTemplateDaclAsync("WebServerACME", Arg.Any<CancellationToken>());
        Row(report, "template:WebServerACME").Title.Should().Contain("Web Server ACME");
    }

    [Fact]
    public async Task ATemplateNamedBothWays_IsOneRow_ReadOnce()
    {
        // The Settings page passes the enabled templates as stored, and issue
        // #17 lets one template be stored by either name.
        var report = await Create().RunAsync(Ca, ["WebServerACME", "Web Server ACME"]);

        report.Rows.Where(r => r.Id == "template:WebServerACME").Should().ContainSingle();
        await _probe.Received(1).ReadTemplateDaclAsync("WebServerACME", Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ATemplateTheCaDoesNotPublish_FailsWithoutADirectoryRead()
    {
        var report = await Create().RunAsync(Ca, ["Gone"]);

        Row(report, "template:Gone").Status.Should().Be(RightsStatus.Failed);
        await _probe.DidNotReceive().ReadTemplateDaclAsync("Gone", Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task MoreTemplatesThanTheLimit_AreRefused()
    {
        var many = Enumerable.Range(0, ServiceRightsCheck.MaxTemplates + 1).Select(i => $"T{i}").ToList();

        var run = () => Create().RunAsync(Ca, many);

        await run.Should().ThrowAsync<ArgumentException>();
    }

    // Evidence of an earlier enrolment. Every condition must hold, so each
    // test below breaks exactly one of them.

    private static (X509Certificate2 CaCertificate, X509Certificate2 Leaf) IssueHttpsCertificate(
        string friendlyName, string caName = "CN=Example CA")
    {
        using var caKey = RSA.Create(2048);
        var caRequest = new CertificateRequest(caName, caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        var caCertificate = caRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        using var leafKey = RSA.Create(2048);
        var leafRequest = new CertificateRequest("CN=ducks01.corp.example.com", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var leaf = leafRequest.Create(caCertificate, DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddDays(90), [1, 2, 3, 4]);
        leaf.FriendlyName = friendlyName;
        return (caCertificate, leaf);
    }

    private void RecordHttpsCertificate(string? template)
    {
        SettingsOverlay.Save(
            new SettingsOverlay.OverlaySettings(
                CaConnectionString: Ca, ExternalUrl: null,
                HttpsCertificateThumbprint: "AB12", HttpsCertificateTemplate: template),
            _options.SettingsOverlayPath!);
    }

    [Fact]
    public async Task AnInstalledHttpsCertificateFromThisCa_ProvesItsTemplate()
    {
        var (caCertificate, leaf) = IssueHttpsCertificate(ServiceRightsCheck.HttpsCertificateFriendlyName);
        RecordHttpsCertificate("WebServerACME");
        _store.Find("AB12").Returns(_ => new X509Certificate2(leaf));
        _client.GetCaCertificateChainAsync(Arg.Any<CancellationToken>()).Returns(new List<byte[]> { caCertificate.RawData });

        var report = await Create().RunAsync(Ca, ["WebServerACME"]);

        Row(report, "https-enrolment").Status.Should().Be(RightsStatus.Proven);
        Row(report, "template:WebServerACME").Status.Should().Be(RightsStatus.Proven);
    }

    [Fact]
    public async Task ACertificateFromAnotherCa_ProvesNothing()
    {
        // A thumbprint left behind by an earlier install against a different
        // CA: installed, ours, and still no proof about the CA being checked.
        var (_, leaf) = IssueHttpsCertificate(ServiceRightsCheck.HttpsCertificateFriendlyName, "CN=Previous CA");
        var (thisCa, _) = IssueHttpsCertificate(ServiceRightsCheck.HttpsCertificateFriendlyName);
        RecordHttpsCertificate("WebServerACME");
        _store.Find("AB12").Returns(_ => new X509Certificate2(leaf));
        _client.GetCaCertificateChainAsync(Arg.Any<CancellationToken>()).Returns(new List<byte[]> { thisCa.RawData });

        var report = await Create().RunAsync(Ca, ["WebServerACME"]);

        Row(report, "https-enrolment").Status.Should().Be(RightsStatus.Unproven);
        Row(report, "template:WebServerACME").Status.Should().Be(RightsStatus.Inferred);
    }

    [Fact]
    public async Task ACertificateWeDidNotInstall_ProvesNothing()
    {
        var (caCertificate, leaf) = IssueHttpsCertificate("Imported by hand");
        RecordHttpsCertificate("WebServerACME");
        _store.Find("AB12").Returns(_ => new X509Certificate2(leaf));
        _client.GetCaCertificateChainAsync(Arg.Any<CancellationToken>()).Returns(new List<byte[]> { caCertificate.RawData });

        var report = await Create().RunAsync(Ca, ["WebServerACME"]);

        Row(report, "https-enrolment").Status.Should().Be(RightsStatus.Unproven);
    }

    [Fact]
    public async Task ARecordWithNoTemplate_ProvesNothing()
    {
        var (caCertificate, leaf) = IssueHttpsCertificate(ServiceRightsCheck.HttpsCertificateFriendlyName);
        RecordHttpsCertificate(template: null);
        _store.Find("AB12").Returns(_ => new X509Certificate2(leaf));
        _client.GetCaCertificateChainAsync(Arg.Any<CancellationToken>()).Returns(new List<byte[]> { caCertificate.RawData });

        var report = await Create().RunAsync(Ca, ["WebServerACME"]);

        Row(report, "https-enrolment").Status.Should().Be(RightsStatus.Unproven);
    }

    [Fact]
    public async Task ACertificateNoLongerInTheStore_ProvesNothing()
    {
        RecordHttpsCertificate("WebServerACME");
        _store.Find("AB12").Returns((X509Certificate2?)null);

        var report = await Create().RunAsync(Ca, ["WebServerACME"]);

        Row(report, "https-enrolment").Status.Should().Be(RightsStatus.Unproven);
    }

    /// <summary>
    /// A real time safety net around a wait that should complete at once. It
    /// asks the thread pool before calling a pending wait a regression, the
    /// pattern CertificateSyncTriggerTests.Bounded documents (issue #381): a
    /// fixed bound elapsing on a starved pool proves nothing about the code.
    /// </summary>
    private static async Task<T> Bounded<T>(Task<T> wait)
    {
        var elapsed = Stopwatch.StartNew();
        while (true)
        {
            try
            {
                return await wait.WaitAsync(TimeSpan.FromSeconds(30));
            }
            catch (TimeoutException)
            {
                if (elapsed.Elapsed >= TimeSpan.FromMinutes(5))
                    throw new TimeoutException("The check never finished and the thread pool never became responsive.");

                var ran = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                ThreadPool.UnsafeQueueUserWorkItem(static tcs => tcs.TrySetResult(), ran, preferLocal: false);
                try
                {
                    await ran.Task.WaitAsync(TimeSpan.FromSeconds(5));
                }
                catch (TimeoutException)
                {
                    continue; // Starved: the bound proved nothing.
                }

                try
                {
                    return await wait.WaitAsync(TimeSpan.FromSeconds(1));
                }
                catch (TimeoutException)
                {
                    throw new TimeoutException(
                        "The check was still running with a responsive thread pool, so a deadline did not fire. " +
                        "This is a regression in ServiceRightsCheck, not a loaded box.");
                }
            }
        }
    }
}

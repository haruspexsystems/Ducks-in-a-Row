using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Certus.Core.Adcs;
using Certus.Core.Configuration;
using Certus.Core.Setup;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Certus.Core.ServiceRights;

/// <summary>
/// Proves what it can of the service's rights on a CA before first use, and says
/// plainly what it cannot (issue #440).
///
/// It runs inside the service, so every reading is taken as the account that
/// will do the work: LocalSystem, which the CA and the directory see as this
/// server's computer account. It is never run under impersonation of the
/// administrator driving the page, whose rights are the wrong answer.
///
/// Read only by construction. The CA calls are Test Connection's two property
/// reads, a one row read of the certificate view, <c>ICertAdmin2::GetMyRoles</c>
/// and the CA's certificate chain; the directory calls read the account's
/// groups and the templates' permission lists. Nothing is submitted, issued or
/// revoked.
///
/// Every reading has a deadline, because a COM or LDAP call cannot be
/// cancelled once it is in flight: one that runs over is abandoned, its
/// eventual failure is observed so it is not an unobserved task exception, and
/// the row reads Unproven. A caller that cancels gets an exception, not a
/// report built on half the readings.
/// </summary>
public sealed class ServiceRightsCheck
{
    public static readonly TimeSpan ComponentsDeadline = TimeSpan.FromSeconds(10);
    public static readonly TimeSpan CaCallDeadline = TimeSpan.FromSeconds(30);
    public static readonly TimeSpan DirectoryDeadline = TimeSpan.FromSeconds(20);

    /// <summary>
    /// The most templates one check reads. Each costs a directory search, and an
    /// estate exposing more than this over ACME is not the one this page serves.
    /// </summary>
    public const int MaxTemplates = 16;

    private const int ClassNotRegisteredHResult = unchecked((int)0x80040154);
    private const int MemberNotFoundHResult = unchecked((int)0x80020003);

    private readonly IAdcsClientFactory _clientFactory;
    private readonly IServiceRightsProbe _probe;
    private readonly IHttpsCertificateStore _certificateStore;
    private readonly CertusOptions _options;
    private readonly ILogger<ServiceRightsCheck> _logger;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;
    private readonly ServiceRightsFindings _findings;

    public ServiceRightsCheck(
        IAdcsClientFactory clientFactory,
        IServiceRightsProbe probe,
        IHttpsCertificateStore certificateStore,
        IOptions<CertusOptions> options,
        ILogger<ServiceRightsCheck> logger)
        : this(clientFactory, probe, certificateStore, options, logger, Task.Delay, ServiceRightsFindings.MeasuredOnLab2019)
    {
    }

    /// <summary>
    /// For tests: <paramref name="delay"/> stands in for the deadline, so a
    /// deadline can fire without any clock, and <paramref name="findings"/> lets
    /// both answers of each measurement be exercised.
    /// </summary>
    internal ServiceRightsCheck(
        IAdcsClientFactory clientFactory,
        IServiceRightsProbe probe,
        IHttpsCertificateStore certificateStore,
        IOptions<CertusOptions> options,
        ILogger<ServiceRightsCheck> logger,
        Func<TimeSpan, CancellationToken, Task> delay,
        ServiceRightsFindings findings)
    {
        _clientFactory = clientFactory;
        _probe = probe;
        _certificateStore = certificateStore;
        _options = options.Value;
        _logger = logger;
        _delay = delay;
        _findings = findings;
    }

    /// <summary>
    /// Checks the service's rights on <paramref name="caConnectionString"/> and on
    /// each of <paramref name="templates"/>.
    /// </summary>
    /// <param name="caConnectionString">The CA, in <c>HOST\CA Name</c> form, already validated.</param>
    /// <param name="templates">Template names in either form, already validated. At most <see cref="MaxTemplates"/>.</param>
    /// <param name="cancellationToken">Cancels the check; the report is then not produced.</param>
    public async Task<ServiceRightsReport> RunAsync(
        string caConnectionString,
        IReadOnlyList<string> templates,
        CancellationToken cancellationToken = default)
    {
        if (templates.Count > MaxTemplates)
            throw new ArgumentException($"At most {MaxTemplates} templates can be checked at once.", nameof(templates));

        // Local and directory readings do not depend on the CA, so they run
        // alongside it.
        var componentsTask = WithDeadline(
            ct => Guard(() => _probe.CheckComponentsAsync(ct), ex => new ComponentsReading(
                [new ComponentReading("CertRequest", ReadingOutcome.Failed, ex.HResult, ex.Message)])),
            ComponentsDeadline, cancellationToken);
        var principalTask = WithDeadline(
            ct => Guard(() => _probe.ReadServicePrincipalAsync(ct), ex => new PrincipalReading(
                ReadingOutcome.Failed, null, null, ProcessIdentityFallback(), false, null, null, [], ex.Message)),
            DirectoryDeadline, cancellationToken);

        var client = _clientFactory.Create(caConnectionString);
        try
        {
            var connect = await ObserveConnectAsync(client, cancellationToken).ConfigureAwait(false);
            var blocked = connect.Outcome is CaCallOutcome.Unavailable or CaCallOutcome.ComponentsMissing or CaCallOutcome.TimedOut;

            var rolesTask = blocked
                ? Task.FromResult<CaRolesReading?>(null)
                : WithDeadline(
                    ct => Guard(() => _probe.ReadCaRolesAsync(caConnectionString, ct),
                        ex => new CaRolesReading(ReadingOutcome.Failed, null, ex.HResult, ex.Message)),
                    CaCallDeadline, cancellationToken);
            var viewTask = blocked
                ? Task.FromResult(CaCallObservation.NotAttempted)
                : ObserveViewAsync(client, cancellationToken);

            var principal = await principalTask.ConfigureAwait(false);
            var templateObservations = await ObserveTemplatesAsync(
                client, templates, connect, principal, cancellationToken).ConfigureAwait(false);
            var evidence = await FindEvidenceAsync(client, connect, cancellationToken).ConfigureAwait(false);

            var observations = new ServiceRightsObservations(
                await componentsTask.ConfigureAwait(false),
                principal,
                connect,
                await rolesTask.ConfigureAwait(false),
                await viewTask.ConfigureAwait(false),
                templateObservations,
                evidence,
                _probe.Simulated);

            var rows = ServiceRightsRows.Build(observations, _findings);
            var identity = new ServiceRightsIdentity(
                principal?.ProcessIdentity ?? ProcessIdentityFallback(),
                principal?.IsMachineIdentity ?? false,
                principal?.AccountName,
                principal?.AccountSid,
                principal?.DomainName,
                principal?.GroupSids.Count ?? 0);

            _logger.LogInformation(
                "Service rights check for {Ca} as {Account}{Simulated}: {Rows}",
                caConnectionString,
                identity.AccountName ?? identity.ProcessIdentity,
                _probe.Simulated ? " (simulated)" : "",
                string.Join(", ", rows.Select(r => $"{r.Id}={ServiceRightsWire.Status(r.Status)}")));

            return new ServiceRightsReport(caConnectionString, identity, rows, _probe.Simulated, DateTimeOffset.UtcNow);
        }
        finally
        {
            (client as IDisposable)?.Dispose();
        }
    }

    private async Task<CaCallObservation> ObserveConnectAsync(IAdcsClient client, CancellationToken cancellationToken)
    {
        var observed = await WithDeadline(async ct =>
        {
            try
            {
                var info = await client.GetCaInfoAsync(ct).ConfigureAwait(false);
                return info.IsAccessible
                    ? new CaCallObservation(CaCallOutcome.Answered, info.Name)
                    : new CaCallObservation(CaCallOutcome.Failed, "The CA did not answer the property reads.");
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (CaAccessDeniedException ex)
            {
                return new CaCallObservation(CaCallOutcome.AccessDenied, ex.Message);
            }
            catch (CaUnavailableException ex)
            {
                return new CaCallObservation(CaCallOutcome.Unavailable, ex.Message);
            }
            catch (COMException ex) when (ex.HResult is ClassNotRegisteredHResult or MemberNotFoundHResult)
            {
                return new CaCallObservation(CaCallOutcome.ComponentsMissing, ex.Message);
            }
            catch (Exception ex)
            {
                return new CaCallObservation(CaCallOutcome.Failed, ex.Message);
            }
        }, CaCallDeadline, cancellationToken).ConfigureAwait(false);

        return observed ?? new CaCallObservation(CaCallOutcome.TimedOut);
    }

    /// <summary>
    /// A one row read of the certificate view, by a request id no CA will have
    /// reached. The inventory sync reads the same view, so the view opening is
    /// the proof; whether a row comes back does not matter.
    /// </summary>
    private async Task<CaCallObservation> ObserveViewAsync(IAdcsClient client, CancellationToken cancellationToken)
    {
        var observed = await WithDeadline(async ct =>
        {
            try
            {
                await client.GetRequestStatusAsync(int.MaxValue, ct).ConfigureAwait(false);
                return new CaCallObservation(CaCallOutcome.Answered);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (CaAccessDeniedException ex)
            {
                return new CaCallObservation(CaCallOutcome.AccessDenied, ex.Message);
            }
            catch (CaUnavailableException ex)
            {
                return new CaCallObservation(CaCallOutcome.Unavailable, ex.Message);
            }
            catch (Exception ex)
            {
                return new CaCallObservation(CaCallOutcome.Failed, ex.Message);
            }
        }, CaCallDeadline, cancellationToken).ConfigureAwait(false);

        return observed ?? new CaCallObservation(CaCallOutcome.TimedOut);
    }

    private async Task<IReadOnlyList<TemplateObservation>> ObserveTemplatesAsync(
        IAdcsClient client,
        IReadOnlyList<string> templates,
        CaCallObservation connect,
        PrincipalReading? principal,
        CancellationToken cancellationToken)
    {
        if (templates.Count == 0)
            return [];

        // The CA's own list resolves a display name to the programmatic name the
        // directory knows the template by, and says whether it is published. It
        // reads through the same interface as Test Connection, so it is only
        // worth asking when that answered.
        IReadOnlyList<TemplateInfo>? published = null;
        if (connect.Outcome == CaCallOutcome.Answered)
        {
            published = await WithDeadline(async ct =>
            {
                try
                {
                    return await client.GetTemplatesAsync(ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Service rights check: the CA's template list could not be read");
                    return null;
                }
            }, CaCallDeadline, cancellationToken).ConfigureAwait(false);
        }

        // Resolved first and then made distinct, because one template can be
        // asked about by both of its names (the dual form of issue #17), and two
        // rows for it would carry one id and read it twice.
        var resolved = templates
            .Select(requested =>
            {
                var match = published?.FirstOrDefault(t =>
                    t.Name.Equals(requested, StringComparison.OrdinalIgnoreCase)
                    || t.DisplayName.Equals(requested, StringComparison.OrdinalIgnoreCase));
                return (
                    Name: match?.Name ?? requested,
                    DisplayName: match?.DisplayName ?? requested,
                    Published: published is null ? (bool?)null : match is not null);
            })
            .DistinctBy(t => t.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var principalRead = principal is { Outcome: ReadingOutcome.Ok, AccountSid: not null };
        var reads = resolved.Select(async template =>
        {
            if (!principalRead || template.Published == false)
                return new TemplateObservation(template.Name, template.DisplayName, template.Published, null);

            var dacl = await WithDeadline(
                ct => Guard(() => _probe.ReadTemplateDaclAsync(template.Name, ct),
                    ex => new TemplateDaclReading(template.Name, ReadingOutcome.Failed, [], Detail: ex.Message)),
                DirectoryDeadline, cancellationToken).ConfigureAwait(false);
            return new TemplateObservation(template.Name, template.DisplayName, template.Published, dacl, DaclTimedOut: dacl is null);
        });

        return await Task.WhenAll(reads).ConfigureAwait(false);
    }

    /// <summary>
    /// The HTTPS certificate the wizard or the Settings page enrolled, when it is
    /// still installed and was issued by this CA. That certificate is the one
    /// exercise of Request Certificates and of one template's Enroll this server
    /// has on record. Every condition must hold, because a thumbprint alone
    /// could name a certificate from a previous CA or one imported by hand.
    /// </summary>
    private async Task<EnrollmentEvidence?> FindEvidenceAsync(
        IAdcsClient client, CaCallObservation connect, CancellationToken cancellationToken)
    {
        if (_probe.Simulated || connect.Outcome != CaCallOutcome.Answered)
            return null;

        SettingsOverlay.OverlaySettings overlay;
        try
        {
            overlay = SettingsOverlay.Load(SettingsOverlay.ResolvePath(_options));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Service rights check: the settings overlay could not be read");
            return null;
        }

        if (string.IsNullOrWhiteSpace(overlay.HttpsCertificateThumbprint)
            || string.IsNullOrWhiteSpace(overlay.HttpsCertificateTemplate))
            return null;

        using var certificate = _certificateStore.Find(overlay.HttpsCertificateThumbprint);
        if (certificate is null
            || !string.Equals(certificate.FriendlyName, HttpsCertificateFriendlyName, StringComparison.Ordinal))
            return null;

        var chain = await WithDeadline(async ct =>
        {
            try
            {
                return await client.GetCaCertificateChainAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Service rights check: the CA's certificate could not be read to match the HTTPS certificate");
                return null;
            }
        }, CaCallDeadline, cancellationToken).ConfigureAwait(false);

        if (chain is not { Count: > 0 })
            return null;

        using var caCertificate = X509CertificateLoader.LoadCertificate(chain[0]);
        if (!certificate.IssuerName.RawData.AsSpan().SequenceEqual(caCertificate.SubjectName.RawData))
            return null;

        return new EnrollmentEvidence(overlay.HttpsCertificateTemplate, new DateTimeOffset(certificate.NotBefore.ToUniversalTime(), TimeSpan.Zero));
    }

    /// <summary>
    /// The friendly name every HTTPS certificate this product installs carries,
    /// the value of <c>MachineHttpsCertificateStore.FriendlyName</c>. Repeated
    /// rather than referenced because that class is Windows only and this
    /// assembly is not.
    /// </summary>
    internal const string HttpsCertificateFriendlyName = "Ducks in a Row HTTPS";

    /// <summary>
    /// Runs <paramref name="work"/> with a deadline. Null means the deadline won:
    /// the work is abandoned, since a COM or LDAP call in flight cannot be
    /// stopped, and its eventual failure is observed. A caller that cancelled
    /// gets <see cref="OperationCanceledException"/> instead.
    /// </summary>
    private async Task<T?> WithDeadline<T>(
        Func<CancellationToken, Task<T>> work, TimeSpan limit, CancellationToken cancellationToken)
        where T : class?
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var task = work(linked.Token);
        var deadline = _delay(limit, linked.Token);

        var first = await Task.WhenAny(task, deadline).ConfigureAwait(false);
        if (first == task)
        {
            linked.Cancel();
            return await task.ConfigureAwait(false);
        }

        cancellationToken.ThrowIfCancellationRequested();
        linked.Cancel();
        _ = task.ContinueWith(
            static t => _ = t.Exception,
            CancellationToken.None,
            TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
        return null;
    }

    /// <summary>
    /// Holds a probe to its contract: a reading that throws anyway, other than
    /// for cancellation, becomes the failure reading <paramref name="onFailure"/>
    /// builds, so one broken reading cannot take the whole report down.
    /// </summary>
    private static async Task<T> Guard<T>(Func<Task<T>> read, Func<Exception, T> onFailure)
    {
        try
        {
            return await read().ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return onFailure(ex);
        }
    }

    private static string ProcessIdentityFallback() => $@"{Environment.UserDomainName}\{Environment.UserName}";
}

using Certus.Core.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Certus.Core.Data.Retention;

/// <summary>
/// Runs <see cref="DataRetentionJob"/> once a day (issue #637). The first pass
/// waits <see cref="StartupDelay"/> so the startup migration, the status file
/// checks and the first certificate sync are not competing with housekeeping;
/// after that one pass every <see cref="Interval"/>.
///
/// <para>It runs in monitor mode too: retention is a write to this database,
/// never to the CA, and a monitor only install keeps alert history and
/// deactivated accounts like any other. When every period is 0 it logs that
/// once and exits, since settings are read at startup and cannot change under
/// it.</para>
///
/// <para>One failed pass is logged and the next runs as scheduled, the stance
/// every other background monitor in the product takes.</para>
/// </summary>
public sealed class DataRetentionService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly RetentionOptions _options;
    private readonly ILogger<DataRetentionService> _logger;
    private readonly TimeProvider _time;

    /// <summary>The settling delay before the first pass.</summary>
    internal TimeSpan StartupDelay { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>How often the rule is applied.</summary>
    internal TimeSpan Interval { get; init; } = TimeSpan.FromHours(24);

    public DataRetentionService(
        IServiceScopeFactory scopeFactory,
        IOptions<RetentionOptions> options,
        ILogger<DataRetentionService> logger,
        TimeProvider? timeProvider = null)
    {
        _scopeFactory = scopeFactory ?? throw new ArgumentNullException(nameof(scopeFactory));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _time = timeProvider ?? TimeProvider.System;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (_options.EverythingDisabled)
        {
            _logger.LogInformation(
                "Data retention is turned off: every period under Certus:Retention is 0, so nothing is ever removed.");
            return;
        }

        _logger.LogInformation(
            "Data retention started: finished orders {OrderDays} day(s), deactivated accounts {AccountDays} day(s), " +
            "alert history {AlertDays} day(s), administrator audit trail {AuditDays} day(s) " +
            "(0 keeps a class for ever); one pass every {Interval} hour(s).",
            _options.FinishedOrderDays, _options.DeactivatedAccountDays, _options.AlertHistoryDays,
            _options.EffectiveAuditTrailDays, Interval.TotalHours);

        try
        {
            await Task.Delay(StartupDelay, _time, stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await RunOnceAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "The data retention pass failed. The next one runs as scheduled.");
            }

            try
            {
                await Task.Delay(Interval, _time, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    /// <summary>
    /// One pass on a fresh scope. Public so a test can drive the hosted
    /// instance without waiting on the timer.
    /// </summary>
    public async Task<DataRetentionReport> RunOnceAsync(CancellationToken cancellationToken = default)
    {
        using var scope = _scopeFactory.CreateScope();
        var job = scope.ServiceProvider.GetRequiredService<DataRetentionJob>();
        return await job.RunAsync(cancellationToken).ConfigureAwait(false);
    }
}

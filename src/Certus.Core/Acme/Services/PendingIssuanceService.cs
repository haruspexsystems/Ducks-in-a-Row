using Certus.Core.Adcs;
using Certus.Core.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Certus.Core.Acme.Services;

/// <summary>
/// Background service that finishes orders the CA did not decide during the
/// finalize request (issue #319).
///
/// <para>
/// An ADCS template with CT_FLAG_PEND_ALL_REQUESTS set holds every request for
/// a CA manager to approve by hand, which is an ordinary configuration rather
/// than an edge case. The finalize submits the CSR, the CA answers "pending",
/// and the order stays "processing" with the request id recorded against it.
/// This worker is what revisits those orders: it asks the CA what became of
/// each held request, delivers the certificate once an operator approves,
/// fails the order if the operator refuses, and gives up when the order
/// outlives the expiry it advertised to the client. Without it "processing"
/// was a resting state that nothing could ever move out of.
/// </para>
///
/// <para>
/// "Pending" here is the CA's word for an undecided request, not the ACME order
/// status of the same name. The orders this sweeps are all in "processing"; an
/// order in ACME's "pending" is one still working through its challenges and is
/// none of this worker's business.
/// </para>
/// </summary>
public sealed class PendingIssuanceService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<PendingIssuanceService> _logger;
    private readonly TimeSpan _pollInterval;

    public PendingIssuanceService(
        IServiceScopeFactory scopeFactory,
        ILogger<PendingIssuanceService> logger,
        IOptions<PendingIssuanceOptions> options)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
        _pollInterval = TimeSpan.FromSeconds(
            Math.Clamp(options.Value.PollIntervalSeconds, 5, 3600));
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation(
            "Pending issuance service started (interval: {Interval} seconds)",
            _pollInterval.TotalSeconds);

        // One tick at a time, and the delay after the work rather than before it,
        // the shape ChallengeValidationService uses. Serial matters more here than
        // it does there: a tick makes one CA round trip per held order, so a slow
        // or unreachable CA can stretch a tick well past the interval, and
        // overlapping ticks would put two sweeps on the same order at once.
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await SweepHeldOrdersAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error resolving orders held at the CA");
            }

            try
            {
                await Task.Delay(_pollInterval, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }

        _logger.LogInformation("Pending issuance service stopped");
    }

    /// <summary>
    /// One sweep. Internal rather than private so Certus.Core.Tests can run a
    /// single tick against a real database and a mock CA without standing the
    /// host up or waiting on the timer.
    /// </summary>
    internal async Task SweepHeldOrdersAsync(CancellationToken cancellationToken)
    {
        using var scope = _scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        var orderService = scope.ServiceProvider.GetRequiredService<OrderService>();

        // Ids only, and no tracking. The resolution re-reads each order through
        // the same scope when its turn comes, because a batch read at the top of a
        // tick is stale by the time a CA round trip or two has passed, and acting
        // on a stale copy is how a claimed order gets written over.
        //
        // Orders with no request id are included on purpose. They are usually a
        // finalize in flight, which the resolution leaves alone, but they are also
        // how a process that died between the claim and the submit leaves an order
        // behind, and those are otherwise unreachable: nothing else will ever look
        // at them again. Filtering them out here would leave that case stuck in
        // exactly the way this service exists to fix.
        var heldOrderIds = await db.AcmeOrders
            .AsNoTracking()
            .Where(o => o.Status == "processing")
            .OrderBy(o => o.Id)
            .Select(o => o.Id)
            .ToListAsync(cancellationToken);

        if (heldOrderIds.Count == 0)
            return;

        _logger.LogDebug("Sweeping {Count} orders claimed for issuance", heldOrderIds.Count);

        var collected = 0;
        var refused = 0;
        var abandoned = 0;
        var remaining = heldOrderIds.Count;

        foreach (var orderId in heldOrderIds)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                var resolution = await orderService.ResolveHeldOrderAsync(orderId, cancellationToken);
                switch (resolution)
                {
                    case HeldOrderResolution.Collected: collected++; break;
                    case HeldOrderResolution.Refused: refused++; break;
                    case HeldOrderResolution.Abandoned: abandoned++; break;
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                // An orderly shutdown that landed inside a CA call, not a failure.
                // Without this it falls into the general arm below and every
                // shutdown mid sweep leaves an Error in the log describing an order
                // that is perfectly fine. The loop's own check reports it as
                // cancellation instead.
                throw;
            }
            catch (CaUnavailableException ex)
            {
                // The CA is down, or none is configured yet, so every remaining
                // order in this batch would fail the same way. Abandon the tick
                // rather than walk the whole list into the same timeout, and say it
                // once. The orders are untouched and the next tick picks them up; a
                // CA outage must never be what fails an order.
                _logger.LogWarning(
                    "The CA is unavailable, so {Count} orders claimed for issuance were left " +
                    "for the next sweep: {Message}",
                    remaining, ex.Message);
                return;
            }
            catch (CaAccessDeniedException ex)
            {
                // Same reasoning, different cause: the service account has lost the
                // rights it needs. Louder, because unlike an outage this one does
                // not clear on its own.
                _logger.LogError(ex,
                    "The CA refused this service's credentials, so {Count} orders claimed for " +
                    "issuance cannot be resolved until that is fixed",
                    remaining);
                return;
            }
            catch (Exception ex)
            {
                // One order's own problem, so the rest of the batch still runs.
                _logger.LogError(ex,
                    "Failed to resolve order {OrderId}, which is claimed for issuance", orderId);
            }

            // Counted after the arms above, so the two that abandon the tick report
            // what is actually left rather than the size of the whole batch.
            remaining--;
        }

        if (collected > 0 || refused > 0 || abandoned > 0)
            _logger.LogInformation(
                "Sweep resolved {Collected} issued, {Refused} refused and {Abandoned} expired " +
                "orders out of {Count} claimed for issuance",
                collected, refused, abandoned, heldOrderIds.Count);
    }
}

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Scheduler.Application.Reconciliation;

namespace Scheduler.Infrastructure.Scheduling;

/// <summary>
/// Hosted reconciliation loop: one sweep at startup (after the scheduler starts)
/// and then a sweep every <see cref="ScheduleOptions.ReconciliationInterval" />.
/// The reconciler itself never throws on a single bad job; this loop only guards
/// against unexpected failures so one sweep cannot silently stop the loop.
/// </summary>
public sealed class ReconciliationService : BackgroundService
{
    private readonly IReconciler _reconciler;
    private readonly ScheduleOptions _options;
    private readonly ILogger<ReconciliationService> _logger;

    public ReconciliationService(
        IReconciler reconciler,
        ScheduleOptions options,
        ILogger<ReconciliationService> logger)
    {
        ArgumentNullException.ThrowIfNull(reconciler);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(logger);

        _reconciler = reconciler;
        _options = options;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await ReconcileAsync(stoppingToken);

            using PeriodicTimer timer = new(_options.ReconciliationInterval);
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                await ReconcileAsync(stoppingToken);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Host shutdown; the loop ends cleanly.
        }
    }

    private async Task ReconcileAsync(CancellationToken cancellationToken)
    {
        try
        {
            ReconciliationResult result = await _reconciler.ReconcileAsync(cancellationToken);
            if (result.Errors.Count > 0)
            {
                SchedulingLog.ReconcileErrors(_logger, result.Errors.Count, string.Join("; ", result.Errors));
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            SchedulingLog.ReconcileSweepFailed(_logger, exception);
        }
    }
}

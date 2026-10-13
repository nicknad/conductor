using Scheduler.Application.Observability;

namespace Scheduler.Host;

/// <summary>
/// A durable-signal-only monitor: on an interval it re-reads the health detail
/// (which derives stuck executions from the executions table) and logs any it
/// finds. It surfaces stuck work; it never kills it and adds no metrics.
/// </summary>
internal sealed class StuckExecutionMonitorService : BackgroundService
{
    private readonly IHealthReportService _health;
    private readonly ObservabilityOptions _options;
    private readonly ILogger<StuckExecutionMonitorService> _logger;

    public StuckExecutionMonitorService(
        IHealthReportService health,
        ObservabilityOptions options,
        ILogger<StuckExecutionMonitorService> logger)
    {
        ArgumentNullException.ThrowIfNull(health);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(logger);

        _health = health;
        _options = options;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await CheckAsync(stoppingToken);

            using PeriodicTimer timer = new(_options.StuckCheckInterval);
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                await CheckAsync(stoppingToken);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Host shutdown; the monitor ends cleanly.
        }
    }

    private async Task CheckAsync(CancellationToken cancellationToken)
    {
        HealthReport report = await _health.GetHealthAsync(cancellationToken);
        if (report.StuckExecutions.Count > 0)
        {
            int count = report.StuckExecutions.Count;
            string ids = string.Join(",", report.StuckExecutions);
            HostLog.StuckExecutionsDetected(_logger, count, ids);
        }
    }
}

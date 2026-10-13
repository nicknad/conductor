using Microsoft.Extensions.Logging;
using Quartz;
using Scheduler.Application.Execution;

namespace Scheduler.Infrastructure.Scheduling;

/// <summary>
/// The single Quartz job type every trigger points at. It reads the stable job
/// id from the merged job data and hands off to the dispatcher. It never touches
/// registry or scheduling state, and never resolves plugin or contract types
/// beyond what the dispatcher exposes.
/// </summary>
public sealed class QuartzBridgeJob : IJob
{
    private readonly IDispatcher _dispatcher;
    private readonly ILogger<QuartzBridgeJob> _logger;

    public QuartzBridgeJob(IDispatcher dispatcher, ILogger<QuartzBridgeJob> logger)
    {
        ArgumentNullException.ThrowIfNull(dispatcher);
        ArgumentNullException.ThrowIfNull(logger);

        _dispatcher = dispatcher;
        _logger = logger;
    }

    public async ValueTask Execute(IJobExecutionContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        string? jobId = context.MergedJobDataMap.GetString(ScheduleJobData.JobId);
        if (string.IsNullOrWhiteSpace(jobId))
        {
            SchedulingLog.MissingJobId(_logger, context.Trigger.Key.ToString(), ScheduleJobData.JobId);
            return;
        }

        try
        {
            await _dispatcher.DispatchAsync(jobId, cancellationToken);
        }
        catch (Exception exception)
        {
            SchedulingLog.DispatchFailed(_logger, jobId, exception);
            throw;
        }
    }
}

using Microsoft.Extensions.Logging;

namespace Scheduler.Infrastructure.Scheduling;

/// <summary>Source-generated, allocation-free log messages for the scheduling layer.</summary>
internal static partial class SchedulingLog
{
    [LoggerMessage(
        EventId = 1,
        Level = LogLevel.Error,
        Message = "Quartz fired trigger '{Trigger}' without a '{Key}' job-data entry.")]
    public static partial void MissingJobId(ILogger logger, string trigger, string key);

    [LoggerMessage(
        EventId = 2,
        Level = LogLevel.Error,
        Message = "Dispatching job '{JobId}' from its Quartz trigger failed.")]
    public static partial void DispatchFailed(ILogger logger, string jobId, Exception exception);

    [LoggerMessage(
        EventId = 3,
        Level = LogLevel.Warning,
        Message = "Reconciliation finished with {ErrorCount} error(s): {Errors}")]
    public static partial void ReconcileErrors(ILogger logger, int errorCount, string errors);

    [LoggerMessage(
        EventId = 4,
        Level = LogLevel.Error,
        Message = "Reconciliation sweep failed; the next sweep will retry.")]
    public static partial void ReconcileSweepFailed(ILogger logger, Exception exception);
}

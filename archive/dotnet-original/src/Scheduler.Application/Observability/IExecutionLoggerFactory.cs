using Scheduler.Contracts.Execution;

namespace Scheduler.Application.Observability;

/// <summary>Identity stamped onto an execution's logs and progress reports.</summary>
public sealed record ExecutionIdentity(
    Guid ExecutionId,
    string CorrelationId,
    string JobId,
    string PluginId,
    Version PluginVersion);

/// <summary>
/// Creates the execution-scoped logger and progress reporter handed to a job.
/// The backend is a singleton, so per-execution state must be created here rather
/// than injected once.
/// </summary>
public interface IExecutionLoggerFactory
{
    IJobExecutionLogger CreateLogger(ExecutionIdentity identity);

    IJobProgressReporter CreateProgressReporter(ExecutionIdentity identity);
}

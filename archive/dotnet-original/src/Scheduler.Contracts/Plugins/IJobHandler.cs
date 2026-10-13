using Scheduler.Contracts.Execution;

namespace Scheduler.Contracts.Plugins;

/// <summary>
/// A single unit of job work. One execution maps to exactly one call of
/// <see cref="ExecuteAsync" />.
/// </summary>
public interface IJobHandler
{
    /// <summary>
    /// Executes the job. The <paramref name="context" /> is a platform-defined
    /// execution context, not a Quartz context; plugins must never depend on
    /// scheduler internals.
    /// </summary>
    /// <remarks>
    /// Handlers run at least once by contract: a crash after an external side
    /// effect but before success is recorded can cause a retry. Handlers with
    /// non-idempotent side effects must account for duplicates.
    /// </remarks>
    Task<JobResult> ExecuteAsync(JobExecutionContext context, CancellationToken cancellationToken);
}

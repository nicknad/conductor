using Scheduler.Application.Observability;
using Scheduler.Contracts.Execution;

namespace Scheduler.Application.Persistence;

/// <summary>Persistence port for the execution store (run status, attempts, results).</summary>
public interface IExecutionRepository
{
    Task<ExecutionRecord?> GetAsync(Guid executionId, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<ExecutionRecord>> ListByJobAsync(string jobId, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<ExecutionRecord>> ListByStatusAsync(JobExecutionStatus status, CancellationToken cancellationToken = default);

    /// <summary>Lists executions matching <paramref name="filter" />, newest first.</summary>
    Task<IReadOnlyList<ExecutionRecord>> ListAsync(ExecutionFilter filter, CancellationToken cancellationToken = default);

    Task CreateAsync(ExecutionRecord execution, CancellationToken cancellationToken = default);

    /// <summary>Replaces the mutable execution fields (status, timestamps, result).</summary>
    Task UpdateAsync(ExecutionRecord execution, CancellationToken cancellationToken = default);

    /// <summary>
    /// Transitions every execution still <see cref="JobExecutionStatus.Running" />
    /// to <see cref="JobExecutionStatus.Interrupted" /> at startup, stamping
    /// <paramref name="interruptedAt" /> as the end time. Idempotent. Returns the
    /// number of rows classified.
    /// </summary>
    Task<int> MarkRunningAsInterruptedAsync(DateTimeOffset interruptedAt, CancellationToken cancellationToken = default);
}

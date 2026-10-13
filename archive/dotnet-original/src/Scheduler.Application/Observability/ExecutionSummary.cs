namespace Scheduler.Application.Observability;

/// <summary>
/// The durable done/not-done picture for a time window, computed from SQLite. This
/// is the payload behind <c>GET /api/executions/summary</c>.
/// </summary>
public sealed record ExecutionSummary(
    DateTimeOffset? Since,
    DateTimeOffset Until,
    ExecutionOutcomeCounts Executions,
    RejectionCounts Rejections,
    ScheduleEventCounts Schedules,
    LifecycleCounts Lifecycle,
    ReconciliationCounts Reconciliation);

/// <summary>
/// Execution work in the window. <see cref="Started" /> is the window total and the
/// terminal outcomes partition it; <see cref="Running" /> is the current in-progress
/// count across all time, not the window.
/// </summary>
public sealed record ExecutionOutcomeCounts(
    int Started,
    int Running,
    int Succeeded,
    int Failed,
    int TimedOut,
    int Cancelled,
    int Interrupted,
    int Retries);

/// <summary>Work not admitted, by reason.</summary>
public sealed record RejectionCounts(int Total, IReadOnlyDictionary<string, int> ByReason);

/// <summary>Lifecycle work by operation kind and terminal outcome.</summary>
public sealed record LifecycleCounts(
    IReadOnlyDictionary<string, int> Succeeded,
    IReadOnlyDictionary<string, int> Failed);

/// <summary>Reconciliation repair work and the last durable run.</summary>
public sealed record ReconciliationCounts(int Repaired, int Failed, int Runs, DateTimeOffset? LastSucceededAt);

/// <summary>Builds the window summary from durable state.</summary>
public interface IExecutionSummaryService
{
    Task<ExecutionSummary> GetSummaryAsync(TimeSpan? window, CancellationToken cancellationToken = default);
}

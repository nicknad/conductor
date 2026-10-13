namespace Scheduler.Application.Reconciliation;

/// <summary>
/// Detects and repairs incomplete lifecycle operations and drift between the
/// authoritative registry and the Quartz job store after failures or crashes.
/// </summary>
public interface IReconciler
{
    Task<ReconciliationResult> ReconcileAsync(CancellationToken cancellationToken = default);
}

public sealed record ReconciliationResult(
    int OperationsCompleted,
    int OperationsRolledBack,
    int SchedulesSynchronized,
    IReadOnlyList<string> Errors);

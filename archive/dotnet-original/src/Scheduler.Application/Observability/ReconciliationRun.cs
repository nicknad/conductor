namespace Scheduler.Application.Observability;

/// <summary>A durable record of one reconciliation sweep's outcome.</summary>
public sealed record ReconciliationRun
{
    public long Id { get; init; }

    public required DateTimeOffset Timestamp { get; init; }

    public required int Completed { get; init; }

    public required int RolledBack { get; init; }

    public required int Synchronized { get; init; }

    public required int ErrorCount { get; init; }

    public required bool Succeeded { get; init; }
}

/// <summary>Persistence port for reconciliation-run history.</summary>
public interface IReconciliationRunRepository
{
    Task RecordAsync(ReconciliationRun run, CancellationToken cancellationToken = default);

    Task<ReconciliationRun?> GetLatestAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// In-process view of the reconciler's most recent outcomes, read by the health
/// detail endpoint. Durability lives in <see cref="IReconciliationRunRepository" />.
/// </summary>
public interface IReconciliationStatus
{
    DateTimeOffset? LastSucceededAt { get; }

    DateTimeOffset? LastFailedAt { get; }

    int LastErrorCount { get; }
}

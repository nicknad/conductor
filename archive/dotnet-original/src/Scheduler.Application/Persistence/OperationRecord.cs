namespace Scheduler.Application.Persistence;

/// <summary>The lifecycle or scheduler-change category of a durable operation.</summary>
public enum OperationKind
{
    Install,
    Validate,
    Activate,
    Deactivate,
    Rollback,
    Remove,
    ScheduleChange,
}

/// <summary>Lifecycle state of a durable operation record.</summary>
public enum OperationState
{
    Pending,
    Running,
    Succeeded,
    Failed,
    RolledBack,
}

/// <summary>
/// A durable, resumable record of a lifecycle or scheduler change. Every
/// operation is written before work begins and updated at each phase boundary,
/// so the reconciler can finish or roll it back after a crash.
/// </summary>
public sealed record OperationRecord
{
    public required Guid OperationId { get; init; }

    public required OperationKind Kind { get; init; }

    /// <summary>Opaque, serialized operation payload used for resumption.</summary>
    public required string Payload { get; init; }

    public required OperationState State { get; init; }

    public required DateTimeOffset CreatedAt { get; init; }

    public required DateTimeOffset UpdatedAt { get; init; }
}

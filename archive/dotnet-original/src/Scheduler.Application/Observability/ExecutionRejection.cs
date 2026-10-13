namespace Scheduler.Application.Observability;

/// <summary>Why work was not admitted. Recorded durably so operators can read the reason.</summary>
public enum ExecutionRejectionReason
{
    NotFound,
    Disabled,
    ModeUnavailable,
    NoActiveVersion,
    NoHandler,
    Concurrency,

    /// <summary>The host is shutting down and no longer accepts fire times.</summary>
    ShuttingDown,
}

/// <summary>A durable record of a dispatch that was not admitted.</summary>
public sealed record ExecutionRejection
{
    /// <summary>Storage-assigned identifier; zero until persisted.</summary>
    public long Id { get; init; }

    public required DateTimeOffset Timestamp { get; init; }

    public required string JobId { get; init; }

    public string? PluginId { get; init; }

    public required ExecutionRejectionReason Reason { get; init; }

    /// <summary>Correlation id generated for the rejected dispatch, for cross-referencing.</summary>
    public required string CorrelationId { get; init; }

    public string? Details { get; init; }
}

/// <summary>Persistence port for durable execution-rejection records.</summary>
public interface IExecutionRejectionRepository
{
    Task RecordAsync(ExecutionRejection rejection, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<ExecutionRejection>> ListAsync(
        DateTimeOffset? since,
        int limit,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyDictionary<ExecutionRejectionReason, int>> CountByReasonAsync(
        DateTimeOffset? since,
        CancellationToken cancellationToken = default);
}

/// <summary>Records a rejection with a fresh correlation id and the host clock.</summary>
public interface IExecutionRejectionWriter
{
    Task RecordAsync(
        string jobId,
        string? pluginId,
        ExecutionRejectionReason reason,
        string? details = null,
        CancellationToken cancellationToken = default);
}

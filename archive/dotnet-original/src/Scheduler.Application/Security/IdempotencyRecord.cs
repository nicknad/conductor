namespace Scheduler.Application.Security;

/// <summary>
/// A durable record mapping a caller-supplied operation id to the result of a
/// lifecycle request. A <c>null</c> <see cref="Result" /> means the request is
/// still in flight; replaying it must not start a second execution.
/// </summary>
public sealed record IdempotencyRecord
{
    public required Guid OperationId { get; init; }

    public required string Action { get; init; }

    public required string Target { get; init; }

    public string? Result { get; init; }

    public required DateTimeOffset CreatedAt { get; init; }

    public required DateTimeOffset UpdatedAt { get; init; }
}

/// <summary>Persistence port for operation-scoped idempotency.</summary>
public interface IIdempotencyStore
{
    Task<IdempotencyRecord?> FindAsync(Guid operationId, CancellationToken cancellationToken = default);

    /// <summary>Records still in flight (no result recorded yet).</summary>
    Task<IReadOnlyList<IdempotencyRecord>> ListInFlightAsync(CancellationToken cancellationToken = default);

    /// <summary>Inserts a new in-flight record; returns false when the id already exists.</summary>
    Task<bool> TryBeginAsync(IdempotencyRecord record, CancellationToken cancellationToken = default);

    Task CompleteAsync(
        Guid operationId,
        string result,
        DateTimeOffset updatedAt,
        CancellationToken cancellationToken = default);
}

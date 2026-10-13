namespace Scheduler.Application.Persistence;

/// <summary>
/// Persistence port for durable operation records (the transactional outbox).
/// The state machine is enforced on update; see <see cref="OperationTransitions" />.
/// </summary>
public interface IOperationRepository
{
    Task CreateAsync(OperationRecord operation, CancellationToken cancellationToken = default);

    Task<OperationRecord?> GetAsync(Guid operationId, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<OperationRecord>> ListByStateAsync(OperationState state, CancellationToken cancellationToken = default);

    /// <summary>Operations still requiring reconciliation (not in a terminal state).</summary>
    Task<IReadOnlyList<OperationRecord>> ListNonTerminalAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Advances an operation to <paramref name="state" />, optionally replacing its
    /// payload. Validates the transition and throws when it is not permitted.
    /// </summary>
    Task<OperationRecord> UpdateStateAsync(
        Guid operationId,
        OperationState state,
        string? payload,
        DateTimeOffset updatedAt,
        CancellationToken cancellationToken = default);
}

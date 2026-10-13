using Scheduler.Application.Persistence;
using Scheduler.Application.PluginManagement;

namespace Scheduler.Application.Security;

/// <summary>
/// Wraps a lifecycle mutation with operation-scoped idempotency: the first
/// request with a given operation id runs and records its result; a replay
/// returns that recorded result instead of re-executing; a concurrent duplicate
/// is rejected while the first is still in flight.
/// </summary>
public sealed class LifecycleRequestCoordinator
{
    private readonly IRegistryUnitOfWorkFactory _unitOfWorkFactory;
    private readonly TimeProvider _timeProvider;

    public LifecycleRequestCoordinator(
        IRegistryUnitOfWorkFactory unitOfWorkFactory,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(unitOfWorkFactory);
        ArgumentNullException.ThrowIfNull(timeProvider);

        _unitOfWorkFactory = unitOfWorkFactory;
        _timeProvider = timeProvider;
    }

    public async Task<PluginOperation> RunAsync(
        Guid operationId,
        string action,
        string target,
        Func<CancellationToken, Task<PluginOperation>> operation,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(action);
        ArgumentException.ThrowIfNullOrWhiteSpace(target);
        ArgumentNullException.ThrowIfNull(operation);

        IdempotencyRecord? existing = await FindAsync(operationId, cancellationToken);
        if (existing is not null)
        {
            return Replay(operationId, existing, action, target);
        }

        DateTimeOffset now = _timeProvider.GetUtcNow();
        bool begun;
        await using (IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken))
        {
            begun = await unitOfWork.Idempotency.TryBeginAsync(
                new IdempotencyRecord
                {
                    OperationId = operationId,
                    Action = action,
                    Target = target,
                    Result = null,
                    CreatedAt = now,
                    UpdatedAt = now,
                },
                cancellationToken);
            await unitOfWork.CommitAsync(cancellationToken);
        }

        if (!begun)
        {
            IdempotencyRecord? raced = await FindAsync(operationId, cancellationToken);
            if (raced is not null)
            {
                return Replay(operationId, raced, action, target);
            }

            throw new IdempotentOperationInProgressException(operationId);
        }

        PluginOperation result;
        try
        {
            result = await operation(cancellationToken);
        }
        catch (Exception exception)
        {
            await CompleteAsync(
                operationId,
                new PluginOperation(operationId, string.Empty, null, PluginOperationStatus.Failed, exception.Message),
                CancellationToken.None);
            throw;
        }

        await CompleteAsync(operationId, result, CancellationToken.None);
        return result;
    }

    /// <summary>
    /// Completes any in-flight records left by a crash as a recorded failure, so
    /// a replay returns that durable result instead of reporting in-flight
    /// forever. Returns the number recovered.
    /// </summary>
    public async Task<int> RecoverInterruptedAsync(CancellationToken cancellationToken = default)
    {
        IReadOnlyList<IdempotencyRecord> inFlight;
        await using (IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken))
        {
            inFlight = await unitOfWork.Idempotency.ListInFlightAsync(cancellationToken);
        }

        foreach (IdempotencyRecord record in inFlight)
        {
            PluginOperation interrupted = new(
                record.OperationId,
                string.Empty,
                null,
                PluginOperationStatus.Failed,
                "The operation was interrupted by a restart and was not completed.");
            await CompleteAsync(record.OperationId, interrupted, CancellationToken.None);
        }

        return inFlight.Count;
    }

    private static PluginOperation Replay(Guid operationId, IdempotencyRecord record, string action, string target)
    {
        if (!string.Equals(record.Action, action, StringComparison.Ordinal)
            || !string.Equals(record.Target, target, StringComparison.Ordinal))
        {
            throw new IdempotentOperationConflictException(operationId, action, target, record.Action, record.Target);
        }

        if (record.Result is null)
        {
            throw new IdempotentOperationInProgressException(operationId);
        }

        return OperationPayloadCodec.Deserialize<PluginOperation>(record.Result);
    }

    private async Task<IdempotencyRecord?> FindAsync(Guid operationId, CancellationToken cancellationToken)
    {
        await using IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken);
        return await unitOfWork.Idempotency.FindAsync(operationId, cancellationToken);
    }

    private async Task CompleteAsync(Guid operationId, PluginOperation result, CancellationToken cancellationToken)
    {
        await using IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken);
        await unitOfWork.Idempotency.CompleteAsync(
            operationId,
            OperationPayloadCodec.Serialize(result),
            _timeProvider.GetUtcNow(),
            cancellationToken);
        await unitOfWork.CommitAsync(cancellationToken);
    }
}

/// <summary>Thrown when an operation id is replayed while its first request is still in flight.</summary>
public sealed class IdempotentOperationInProgressException(Guid operationId)
    : Exception($"Operation '{operationId}' is already in progress.")
{
    public Guid OperationId { get; } = operationId;
}

/// <summary>Thrown when an operation id is reused for a different action or target.</summary>
public sealed class IdempotentOperationConflictException(
    Guid operationId,
    string action,
    string target,
    string recordedAction,
    string recordedTarget)
    : Exception(
        $"Operation '{operationId}' was recorded for '{recordedAction}' on '{recordedTarget}', " +
        $"not '{action}' on '{target}'.")
{
    public Guid OperationId { get; } = operationId;
}

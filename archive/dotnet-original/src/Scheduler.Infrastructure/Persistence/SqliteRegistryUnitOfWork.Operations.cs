using Microsoft.Data.Sqlite;
using Scheduler.Application.Persistence;

namespace Scheduler.Infrastructure.Persistence;

internal sealed partial class SqliteRegistryUnitOfWork
{
    private const string OperationColumns = "operation_id, kind, payload, state, created_at, updated_at";

    public async Task CreateAsync(OperationRecord operation, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(operation);

        await using SqliteCommand command = CreateCommand(
            """
            INSERT INTO operations (operation_id, kind, payload, state, created_at, updated_at)
            VALUES ($operationId, $kind, $payload, $state, $createdAt, $updatedAt);
            """);
        command.Parameters.AddWithValue("$operationId", operation.OperationId.ToString("D"));
        command.Parameters.AddWithValue("$kind", operation.Kind.ToString());
        command.Parameters.AddWithValue("$payload", operation.Payload);
        command.Parameters.AddWithValue("$state", operation.State.ToString());
        command.Parameters.AddWithValue("$createdAt", DbTimestamp.Format(operation.CreatedAt));
        command.Parameters.AddWithValue("$updatedAt", DbTimestamp.Format(operation.UpdatedAt));

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    async Task<OperationRecord?> IOperationRepository.GetAsync(
        Guid operationId,
        CancellationToken cancellationToken)
    {
        return await GetOperationAsync(operationId, cancellationToken);
    }

    private async Task<OperationRecord?> GetOperationAsync(
        Guid operationId,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = CreateCommand(
            "SELECT " + OperationColumns + " FROM operations WHERE operation_id = $operationId;");
        command.Parameters.AddWithValue("$operationId", operationId.ToString("D"));

        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadOperation(reader) : null;
    }

    public async Task<IReadOnlyList<OperationRecord>> ListByStateAsync(
        OperationState state,
        CancellationToken cancellationToken = default)
    {
        await using SqliteCommand command = CreateCommand(
            "SELECT " + OperationColumns + " FROM operations WHERE state = $state ORDER BY created_at;");
        command.Parameters.AddWithValue("$state", state.ToString());

        return await ReadOperationsAsync(command, cancellationToken);
    }

    public async Task<IReadOnlyList<OperationRecord>> ListNonTerminalAsync(
        CancellationToken cancellationToken = default)
    {
        await using SqliteCommand command = CreateCommand(
            "SELECT " + OperationColumns +
            " FROM operations WHERE state NOT IN ('Succeeded', 'Failed', 'RolledBack') ORDER BY created_at;");

        return await ReadOperationsAsync(command, cancellationToken);
    }

    public async Task<OperationRecord> UpdateStateAsync(
        Guid operationId,
        OperationState state,
        string? payload,
        DateTimeOffset updatedAt,
        CancellationToken cancellationToken = default)
    {
        OperationRecord existing = await GetOperationAsync(operationId, cancellationToken)
            ?? throw new KeyNotFoundException($"Operation '{operationId}' was not found.");

        OperationTransitions.EnsureCanTransition(existing.State, state);
        string effectivePayload = payload ?? existing.Payload;

        await using SqliteCommand command = CreateCommand(
            """
            UPDATE operations
               SET state = $state, payload = $payload, updated_at = $updatedAt
             WHERE operation_id = $operationId AND state = $fromState;
            """);
        command.Parameters.AddWithValue("$state", state.ToString());
        command.Parameters.AddWithValue("$payload", effectivePayload);
        command.Parameters.AddWithValue("$updatedAt", DbTimestamp.Format(updatedAt));
        command.Parameters.AddWithValue("$operationId", operationId.ToString("D"));
        command.Parameters.AddWithValue("$fromState", existing.State.ToString());

        int affected = await command.ExecuteNonQueryAsync(cancellationToken);
        if (affected == 0)
        {
            throw new InvalidOperationException(
                $"Operation '{operationId}' changed concurrently; expected state '{existing.State}'.");
        }

        return existing with { State = state, Payload = effectivePayload, UpdatedAt = updatedAt };
    }

    private static async Task<IReadOnlyList<OperationRecord>> ReadOperationsAsync(
        SqliteCommand command,
        CancellationToken cancellationToken)
    {
        List<OperationRecord> operations = [];
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            operations.Add(ReadOperation(reader));
        }

        return operations;
    }

    private static OperationRecord ReadOperation(SqliteDataReader reader) => new()
    {
        OperationId = Guid.Parse(reader.GetString(0)),
        Kind = Enum.Parse<OperationKind>(reader.GetString(1)),
        Payload = reader.GetString(2),
        State = Enum.Parse<OperationState>(reader.GetString(3)),
        CreatedAt = DbTimestamp.Parse(reader.GetString(4)),
        UpdatedAt = DbTimestamp.Parse(reader.GetString(5)),
    };
}

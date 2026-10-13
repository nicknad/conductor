using Microsoft.Data.Sqlite;
using Scheduler.Application.Security;

namespace Scheduler.Infrastructure.Persistence;

internal sealed partial class SqliteRegistryUnitOfWork
{
    private const string IdempotencyColumns = "operation_id, action, target, result, created_at, updated_at";

    public async Task<IdempotencyRecord?> FindAsync(
        Guid operationId,
        CancellationToken cancellationToken = default)
    {
        await using SqliteCommand command = CreateCommand(
            "SELECT " + IdempotencyColumns + " FROM idempotency WHERE operation_id = $operationId;");
        command.Parameters.AddWithValue("$operationId", operationId.ToString("D"));

        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadIdempotency(reader) : null;
    }

    public async Task<IReadOnlyList<IdempotencyRecord>> ListInFlightAsync(CancellationToken cancellationToken = default)
    {
        await using SqliteCommand command = CreateCommand(
            "SELECT " + IdempotencyColumns + " FROM idempotency WHERE result IS NULL ORDER BY created_at;");

        List<IdempotencyRecord> records = [];
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            records.Add(ReadIdempotency(reader));
        }

        return records;
    }

    public async Task<bool> TryBeginAsync(IdempotencyRecord record, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(record);

        await using SqliteCommand command = CreateCommand(
            """
            INSERT INTO idempotency (operation_id, action, target, result, created_at, updated_at)
            VALUES ($operationId, $action, $target, NULL, $createdAt, $updatedAt)
            ON CONFLICT (operation_id) DO NOTHING;
            """);
        command.Parameters.AddWithValue("$operationId", record.OperationId.ToString("D"));
        command.Parameters.AddWithValue("$action", record.Action);
        command.Parameters.AddWithValue("$target", record.Target);
        command.Parameters.AddWithValue("$createdAt", DbTimestamp.Format(record.CreatedAt));
        command.Parameters.AddWithValue("$updatedAt", DbTimestamp.Format(record.UpdatedAt));

        return await command.ExecuteNonQueryAsync(cancellationToken) > 0;
    }

    public async Task CompleteAsync(
        Guid operationId,
        string result,
        DateTimeOffset updatedAt,
        CancellationToken cancellationToken = default)
    {
        await using SqliteCommand command = CreateCommand(
            "UPDATE idempotency SET result = $result, updated_at = $updatedAt WHERE operation_id = $operationId;");
        command.Parameters.AddWithValue("$result", result);
        command.Parameters.AddWithValue("$updatedAt", DbTimestamp.Format(updatedAt));
        command.Parameters.AddWithValue("$operationId", operationId.ToString("D"));

        int affected = await command.ExecuteNonQueryAsync(cancellationToken);
        if (affected == 0)
        {
            throw new KeyNotFoundException($"Idempotency record '{operationId}' was not found.");
        }
    }

    private static IdempotencyRecord ReadIdempotency(SqliteDataReader reader) => new()
    {
        OperationId = Guid.Parse(reader.GetString(0)),
        Action = reader.GetString(1),
        Target = reader.GetString(2),
        Result = reader.IsDBNull(3) ? null : reader.GetString(3),
        CreatedAt = DbTimestamp.Parse(reader.GetString(4)),
        UpdatedAt = DbTimestamp.Parse(reader.GetString(5)),
    };
}

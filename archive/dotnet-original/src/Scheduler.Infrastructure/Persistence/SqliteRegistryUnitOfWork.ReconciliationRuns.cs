using Microsoft.Data.Sqlite;
using Scheduler.Application.Observability;

namespace Scheduler.Infrastructure.Persistence;

internal sealed partial class SqliteRegistryUnitOfWork
{
    private const string ReconciliationRunColumns =
        "id, timestamp, completed, rolled_back, synchronized, error_count, succeeded";

    public async Task RecordAsync(ReconciliationRun run, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(run);

        await using SqliteCommand command = CreateCommand(
            """
            INSERT INTO reconciliation_runs
                (timestamp, completed, rolled_back, synchronized, error_count, succeeded)
            VALUES
                ($timestamp, $completed, $rolledBack, $synchronized, $errorCount, $succeeded);
            """);
        command.Parameters.AddWithValue("$timestamp", DbTimestamp.Format(run.Timestamp));
        command.Parameters.AddWithValue("$completed", run.Completed);
        command.Parameters.AddWithValue("$rolledBack", run.RolledBack);
        command.Parameters.AddWithValue("$synchronized", run.Synchronized);
        command.Parameters.AddWithValue("$errorCount", run.ErrorCount);
        command.Parameters.AddWithValue("$succeeded", run.Succeeded ? 1 : 0);

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<ReconciliationRun?> GetLatestAsync(CancellationToken cancellationToken = default)
    {
        await using SqliteCommand command = CreateCommand(
            "SELECT " + ReconciliationRunColumns + " FROM reconciliation_runs ORDER BY id DESC LIMIT 1;");

        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadReconciliationRun(reader) : null;
    }

    private static ReconciliationRun ReadReconciliationRun(SqliteDataReader reader) => new()
    {
        Id = reader.GetInt64(0),
        Timestamp = DbTimestamp.Parse(reader.GetString(1)),
        Completed = reader.GetInt32(2),
        RolledBack = reader.GetInt32(3),
        Synchronized = reader.GetInt32(4),
        ErrorCount = reader.GetInt32(5),
        Succeeded = reader.GetInt64(6) != 0,
    };
}

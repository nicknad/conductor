using Microsoft.Data.Sqlite;
using Scheduler.Application.Observability;

namespace Scheduler.Infrastructure.Persistence;

internal sealed partial class SqliteRegistryUnitOfWork
{
    public async Task RecordAsync(ExecutionRejection rejection, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(rejection);

        await using SqliteCommand command = CreateCommand(
            """
            INSERT INTO execution_rejections (timestamp, job_id, plugin_id, reason, correlation_id, details)
            VALUES ($timestamp, $jobId, $pluginId, $reason, $correlationId, $details);
            """);
        command.Parameters.AddWithValue("$timestamp", DbTimestamp.Format(rejection.Timestamp));
        command.Parameters.AddWithValue("$jobId", rejection.JobId);
        command.Parameters.AddWithValue("$pluginId", rejection.PluginId ?? (object)DBNull.Value);
        command.Parameters.AddWithValue("$reason", rejection.Reason.ToString());
        command.Parameters.AddWithValue("$correlationId", rejection.CorrelationId);
        command.Parameters.AddWithValue("$details", rejection.Details ?? (object)DBNull.Value);

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<ExecutionRejection>> ListAsync(
        DateTimeOffset? since,
        int limit,
        CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(limit);

        await using SqliteCommand command = CreateCommand(
            "SELECT id, timestamp, job_id, plugin_id, reason, correlation_id, details " +
            "FROM execution_rejections WHERE ($since IS NULL OR timestamp >= $since) " +
            "ORDER BY id DESC LIMIT $limit;");
        command.Parameters.AddWithValue("$since", since.HasValue ? DbTimestamp.Format(since.Value) : DBNull.Value);
        command.Parameters.AddWithValue("$limit", limit);

        List<ExecutionRejection> rejections = [];
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            rejections.Add(new ExecutionRejection
            {
                Id = reader.GetInt64(0),
                Timestamp = DbTimestamp.Parse(reader.GetString(1)),
                JobId = reader.GetString(2),
                PluginId = reader.IsDBNull(3) ? null : reader.GetString(3),
                Reason = Enum.Parse<ExecutionRejectionReason>(reader.GetString(4)),
                CorrelationId = reader.GetString(5),
                Details = reader.IsDBNull(6) ? null : reader.GetString(6),
            });
        }

        return rejections;
    }

    public async Task<IReadOnlyDictionary<ExecutionRejectionReason, int>> CountByReasonAsync(
        DateTimeOffset? since,
        CancellationToken cancellationToken = default)
    {
        await using SqliteCommand command = CreateCommand(
            "SELECT reason, COUNT(*) FROM execution_rejections " +
            "WHERE ($since IS NULL OR timestamp >= $since) GROUP BY reason;");
        command.Parameters.AddWithValue("$since", since.HasValue ? DbTimestamp.Format(since.Value) : DBNull.Value);

        Dictionary<ExecutionRejectionReason, int> counts = [];
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            counts[Enum.Parse<ExecutionRejectionReason>(reader.GetString(0))] = reader.GetInt32(1);
        }

        return counts;
    }
}

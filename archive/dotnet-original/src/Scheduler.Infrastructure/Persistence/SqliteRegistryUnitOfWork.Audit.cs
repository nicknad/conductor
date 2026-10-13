using System.Text;
using Microsoft.Data.Sqlite;
using Scheduler.Application.Observability;
using Scheduler.Application.Persistence;

namespace Scheduler.Infrastructure.Persistence;

internal sealed partial class SqliteRegistryUnitOfWork
{
    public async Task WriteAsync(AuditEntry entry, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(entry);

        await using SqliteCommand command = CreateCommand(
            """
            INSERT INTO audit_log (timestamp, actor, action, target, details)
            VALUES ($timestamp, $actor, $action, $target, $details);
            """);
        command.Parameters.AddWithValue("$timestamp", DbTimestamp.Format(entry.Timestamp));
        command.Parameters.AddWithValue("$actor", entry.Actor);
        command.Parameters.AddWithValue("$action", entry.Action);
        command.Parameters.AddWithValue("$target", entry.Target);
        command.Parameters.AddWithValue("$details", entry.Details ?? (object)DBNull.Value);

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<AuditEntry>> ListAsync(
        int limit = 100,
        CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(limit);

        await using SqliteCommand command = CreateCommand(
            "SELECT id, timestamp, actor, action, target, details " +
            "FROM audit_log ORDER BY id DESC LIMIT $limit;");
        command.Parameters.AddWithValue("$limit", limit);

        List<AuditEntry> entries = [];
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            entries.Add(new AuditEntry
            {
                Id = reader.GetInt64(0),
                Timestamp = DbTimestamp.Parse(reader.GetString(1)),
                Actor = reader.GetString(2),
                Action = reader.GetString(3),
                Target = reader.GetString(4),
                Details = reader.IsDBNull(5) ? null : reader.GetString(5),
            });
        }

        return entries;
    }

    public async Task<IReadOnlyList<AuditEntry>> ListAsync(
        AuditFilter filter,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(filter);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(filter.Limit);

        StringBuilder sql = new("SELECT id, timestamp, actor, action, target, details FROM audit_log WHERE 1 = 1");
        if (filter.Actor is not null)
        {
            sql.Append(" AND actor = $actor");
        }

        if (filter.Action is not null)
        {
            sql.Append(" AND action = $action");
        }

        if (filter.Target is not null)
        {
            sql.Append(" AND target = $target");
        }

        if (filter.Since is not null)
        {
            sql.Append(" AND timestamp >= $since");
        }

        sql.Append(" ORDER BY id DESC LIMIT $limit;");

        await using SqliteCommand command = CreateCommand(sql.ToString());
        if (filter.Actor is not null)
        {
            command.Parameters.AddWithValue("$actor", filter.Actor);
        }

        if (filter.Action is not null)
        {
            command.Parameters.AddWithValue("$action", filter.Action);
        }

        if (filter.Target is not null)
        {
            command.Parameters.AddWithValue("$target", filter.Target);
        }

        if (filter.Since is not null)
        {
            command.Parameters.AddWithValue("$since", DbTimestamp.Format(filter.Since.Value));
        }

        command.Parameters.AddWithValue("$limit", filter.Limit);

        List<AuditEntry> entries = [];
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            entries.Add(new AuditEntry
            {
                Id = reader.GetInt64(0),
                Timestamp = DbTimestamp.Parse(reader.GetString(1)),
                Actor = reader.GetString(2),
                Action = reader.GetString(3),
                Target = reader.GetString(4),
                Details = reader.IsDBNull(5) ? null : reader.GetString(5),
            });
        }

        return entries;
    }
}

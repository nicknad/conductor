using Microsoft.Data.Sqlite;
using Scheduler.Application.Observability;

namespace Scheduler.Infrastructure.Persistence;

internal sealed partial class SqliteRegistryUnitOfWork
{
    public async Task RecordAsync(ScheduleEvent scheduleEvent, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scheduleEvent);

        await using SqliteCommand command = CreateCommand(
            """
            INSERT INTO schedule_events (timestamp, job_id, event_kind, misfire_policy)
            VALUES ($timestamp, $jobId, $eventKind, $misfirePolicy);
            """);
        command.Parameters.AddWithValue("$timestamp", DbTimestamp.Format(scheduleEvent.Timestamp));
        command.Parameters.AddWithValue("$jobId", scheduleEvent.JobId);
        command.Parameters.AddWithValue("$eventKind", scheduleEvent.Kind.ToString());
        command.Parameters.AddWithValue(
            "$misfirePolicy",
            scheduleEvent.MisfirePolicy.HasValue ? scheduleEvent.MisfirePolicy.Value.ToString() : DBNull.Value);

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<ScheduleEventCounts> CountAsync(
        DateTimeOffset? since,
        CancellationToken cancellationToken = default)
    {
        await using SqliteCommand command = CreateCommand(
            "SELECT event_kind, COUNT(*) FROM schedule_events " +
            "WHERE ($since IS NULL OR timestamp >= $since) GROUP BY event_kind;");
        command.Parameters.AddWithValue("$since", since.HasValue ? DbTimestamp.Format(since.Value) : DBNull.Value);

        int fired = 0;
        int missed = 0;
        int skipped = 0;
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            int count = reader.GetInt32(1);
            switch (Enum.Parse<ScheduleEventKind>(reader.GetString(0)))
            {
                case ScheduleEventKind.Fired:
                    fired = count;
                    break;
                case ScheduleEventKind.Missed:
                    missed = count;
                    break;
                case ScheduleEventKind.Skipped:
                    skipped = count;
                    break;
            }
        }

        return new ScheduleEventCounts(fired, missed, skipped);
    }
}

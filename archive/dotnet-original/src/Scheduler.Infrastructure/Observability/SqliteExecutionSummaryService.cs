using System.Globalization;
using Microsoft.Data.Sqlite;
using Scheduler.Application.Observability;
using Scheduler.Application.Persistence;
using Scheduler.Contracts.Execution;
using Scheduler.Infrastructure.Persistence;

namespace Scheduler.Infrastructure.Observability;

/// <summary>
/// Computes the done/not-done summary as aggregate queries over the durable
/// tables. Nothing is read from in-process meters, so the numbers survive
/// restarts.
/// </summary>
public sealed class SqliteExecutionSummaryService : IExecutionSummaryService
{
    private readonly ISqliteConnectionFactory _connectionFactory;
    private readonly ObservabilityOptions _options;
    private readonly TimeProvider _timeProvider;

    public SqliteExecutionSummaryService(
        ISqliteConnectionFactory connectionFactory,
        ObservabilityOptions options,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(connectionFactory);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(timeProvider);

        _connectionFactory = connectionFactory;
        _options = options;
        _timeProvider = timeProvider;
    }

    public async Task<ExecutionSummary> GetSummaryAsync(
        TimeSpan? window,
        CancellationToken cancellationToken = default)
    {
        DateTimeOffset until = _timeProvider.GetUtcNow();
        DateTimeOffset since = until - (window ?? _options.SummaryWindow);
        string sinceText = DbTimestamp.Format(since);

        await using SqliteConnection connection = await _connectionFactory.OpenConnectionAsync(cancellationToken);

        ExecutionOutcomeCounts executions = await ReadOutcomesAsync(connection, sinceText, cancellationToken);
        RejectionCounts rejections = await ReadRejectionsAsync(connection, sinceText, cancellationToken);
        ScheduleEventCounts schedules = await ReadSchedulesAsync(connection, sinceText, cancellationToken);
        LifecycleCounts lifecycle = await ReadLifecycleAsync(connection, sinceText, cancellationToken);
        ReconciliationCounts reconciliation = await ReadReconciliationAsync(connection, sinceText, cancellationToken);

        return new ExecutionSummary(since, until, executions, rejections, schedules, lifecycle, reconciliation);
    }

    private static async Task<ExecutionOutcomeCounts> ReadOutcomesAsync(
        SqliteConnection connection,
        string since,
        CancellationToken cancellationToken)
    {
        int succeeded = 0;
        int failed = 0;
        int timedOut = 0;
        int cancelled = 0;
        int interrupted = 0;
        int pending = 0;
        int runningInWindow = 0;

        await using (SqliteCommand command = connection.CreateCommand())
        {
            command.CommandText =
                "SELECT status, COUNT(*) FROM executions WHERE scheduled_at >= $since GROUP BY status;";
            command.Parameters.AddWithValue("$since", since);

            await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                int count = reader.GetInt32(1);
                switch (reader.GetString(0))
                {
                    case nameof(JobExecutionStatus.Succeeded):
                        succeeded = count;
                        break;
                    case nameof(JobExecutionStatus.Failed):
                        failed = count;
                        break;
                    case nameof(JobExecutionStatus.TimedOut):
                        timedOut = count;
                        break;
                    case nameof(JobExecutionStatus.Cancelled):
                        cancelled = count;
                        break;
                    case nameof(JobExecutionStatus.Interrupted):
                        interrupted = count;
                        break;
                    case nameof(JobExecutionStatus.Running):
                        runningInWindow = count;
                        break;
                    case nameof(JobExecutionStatus.Pending):
                        pending = count;
                        break;
                }
            }
        }

        int retries = await ScalarAsync(
            connection,
            "SELECT COALESCE(SUM(attempt - 1), 0) FROM executions WHERE scheduled_at >= $since;",
            since,
            cancellationToken);

        int runningNow = await ScalarAsync(
            connection,
            $"SELECT COUNT(*) FROM executions WHERE status = '{nameof(JobExecutionStatus.Running)}';",
            since: null,
            cancellationToken);

        int started = succeeded + failed + timedOut + cancelled + interrupted + runningInWindow + pending;
        return new ExecutionOutcomeCounts(
            started,
            runningNow,
            succeeded,
            failed,
            timedOut,
            cancelled,
            interrupted,
            retries);
    }

    private static async Task<RejectionCounts> ReadRejectionsAsync(
        SqliteConnection connection,
        string since,
        CancellationToken cancellationToken)
    {
        Dictionary<string, int> byReason = [];
        int total = 0;

        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            "SELECT reason, COUNT(*) FROM execution_rejections WHERE timestamp >= $since GROUP BY reason;";
        command.Parameters.AddWithValue("$since", since);

        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            int count = reader.GetInt32(1);
            byReason[reader.GetString(0)] = count;
            total += count;
        }

        return new RejectionCounts(total, byReason);
    }

    private static async Task<ScheduleEventCounts> ReadSchedulesAsync(
        SqliteConnection connection,
        string since,
        CancellationToken cancellationToken)
    {
        int fired = 0;
        int missed = 0;
        int skipped = 0;

        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            "SELECT event_kind, COUNT(*) FROM schedule_events WHERE timestamp >= $since GROUP BY event_kind;";
        command.Parameters.AddWithValue("$since", since);

        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            int count = reader.GetInt32(1);
            switch (reader.GetString(0))
            {
                case nameof(ScheduleEventKind.Fired):
                    fired = count;
                    break;
                case nameof(ScheduleEventKind.Missed):
                    missed = count;
                    break;
                case nameof(ScheduleEventKind.Skipped):
                    skipped = count;
                    break;
            }
        }

        return new ScheduleEventCounts(fired, missed, skipped);
    }

    private static async Task<LifecycleCounts> ReadLifecycleAsync(
        SqliteConnection connection,
        string since,
        CancellationToken cancellationToken)
    {
        Dictionary<string, int> succeeded = [];
        Dictionary<string, int> failed = [];

        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            "SELECT kind, state, COUNT(*) FROM operations " +
            "WHERE created_at >= $since AND kind <> $scheduleChange GROUP BY kind, state;";
        command.Parameters.AddWithValue("$since", since);
        command.Parameters.AddWithValue("$scheduleChange", nameof(OperationKind.ScheduleChange));

        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            string kind = reader.GetString(0);
            string state = reader.GetString(1);
            int count = reader.GetInt32(2);

            if (state == nameof(OperationState.Succeeded))
            {
                succeeded[kind] = succeeded.GetValueOrDefault(kind) + count;
            }
            else if (state is nameof(OperationState.Failed) or nameof(OperationState.RolledBack))
            {
                failed[kind] = failed.GetValueOrDefault(kind) + count;
            }
        }

        return new LifecycleCounts(succeeded, failed);
    }

    private static async Task<ReconciliationCounts> ReadReconciliationAsync(
        SqliteConnection connection,
        string since,
        CancellationToken cancellationToken)
    {
        int repaired = await ScalarAsync(
            connection,
            "SELECT COUNT(*) FROM operations " +
            "WHERE kind = $kind AND state = $state AND updated_at >= $since;",
            since,
            cancellationToken,
            ("$kind", nameof(OperationKind.ScheduleChange)),
            ("$state", nameof(OperationState.Succeeded)));

        int failed = await ScalarAsync(
            connection,
            "SELECT COUNT(*) FROM operations " +
            "WHERE kind = $kind AND state = $state AND updated_at >= $since;",
            since,
            cancellationToken,
            ("$kind", nameof(OperationKind.ScheduleChange)),
            ("$state", nameof(OperationState.Failed)));

        int runs = await ScalarAsync(
            connection,
            "SELECT COUNT(*) FROM reconciliation_runs WHERE timestamp >= $since;",
            since,
            cancellationToken);

        DateTimeOffset? lastSucceeded = await ScalarTimestampAsync(
            connection,
            "SELECT MAX(timestamp) FROM reconciliation_runs WHERE succeeded = 1;",
            cancellationToken);

        return new ReconciliationCounts(repaired, failed, runs, lastSucceeded);
    }

    private static async Task<int> ScalarAsync(
        SqliteConnection connection,
        string sql,
        string? since,
        CancellationToken cancellationToken,
        params (string Name, object Value)[] extraParameters)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = sql;
        if (since is not null)
        {
            command.Parameters.AddWithValue("$since", since);
        }

        foreach ((string name, object value) in extraParameters)
        {
            command.Parameters.AddWithValue(name, value);
        }

        object? result = await command.ExecuteScalarAsync(cancellationToken);
        return result is null or DBNull ? 0 : Convert.ToInt32(result, CultureInfo.InvariantCulture);
    }

    private static async Task<DateTimeOffset?> ScalarTimestampAsync(
        SqliteConnection connection,
        string sql,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = sql;
        object? result = await command.ExecuteScalarAsync(cancellationToken);
        return result is null or DBNull ? null : DbTimestamp.Parse((string)result);
    }
}

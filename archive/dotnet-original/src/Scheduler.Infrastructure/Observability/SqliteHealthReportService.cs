using System.Data.Common;
using System.IO;
using Microsoft.Data.Sqlite;
using Scheduler.Application.Observability;
using Scheduler.Contracts.Execution;
using Scheduler.Infrastructure.Persistence;

namespace Scheduler.Infrastructure.Observability;

/// <summary>
/// Operational health detail: database reachability, reconciler last success, and
/// executions that look stuck. Never throws; failures are reported as unhealthy
/// components.
/// </summary>
public sealed class SqliteHealthReportService : IHealthReportService
{
    private readonly ISqliteConnectionFactory _connectionFactory;
    private readonly IReconciliationStatus _reconciliation;
    private readonly ObservabilityOptions _options;
    private readonly TimeProvider _timeProvider;

    public SqliteHealthReportService(
        ISqliteConnectionFactory connectionFactory,
        IReconciliationStatus reconciliation,
        ObservabilityOptions options,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(connectionFactory);
        ArgumentNullException.ThrowIfNull(reconciliation);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(timeProvider);

        _connectionFactory = connectionFactory;
        _reconciliation = reconciliation;
        _options = options;
        _timeProvider = timeProvider;
    }

    public async Task<HealthReport> GetHealthAsync(CancellationToken cancellationToken = default)
    {
        DateTimeOffset now = _timeProvider.GetUtcNow();
        HealthComponent database;
        IReadOnlyList<Guid> stuck = [];

        try
        {
            await using SqliteConnection connection = await _connectionFactory.OpenConnectionAsync(cancellationToken);
            await using (SqliteCommand command = connection.CreateCommand())
            {
                command.CommandText = "SELECT 1;";
                await command.ExecuteScalarAsync(cancellationToken);
            }

            database = new HealthComponent(true, "reachable");
            stuck = await ReadStuckAsync(
                connection,
                DbTimestamp.Format(now - _options.ExecutionHeartbeat),
                cancellationToken);
        }
        catch (DbException exception)
        {
            database = new HealthComponent(false, exception.Message);
        }
        catch (IOException exception)
        {
            database = new HealthComponent(false, exception.Message);
        }

        HealthComponent reconciler = DescribeReconciler();
        bool healthy = database.Healthy && reconciler.Healthy && stuck.Count == 0;
        return new HealthReport(healthy, now, database, reconciler, stuck);
    }

    private static async Task<IReadOnlyList<Guid>> ReadStuckAsync(
        SqliteConnection connection,
        string threshold,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            "SELECT execution_id FROM executions " +
            "WHERE status = $running AND started_at IS NOT NULL AND started_at < $threshold;";
        command.Parameters.AddWithValue("$running", nameof(JobExecutionStatus.Running));
        command.Parameters.AddWithValue("$threshold", threshold);

        List<Guid> stuck = [];
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            stuck.Add(Guid.Parse(reader.GetString(0)));
        }

        return stuck;
    }

    private HealthComponent DescribeReconciler()
    {
        DateTimeOffset? succeededAt = _reconciliation.LastSucceededAt;
        DateTimeOffset? failedAt = _reconciliation.LastFailedAt;
        int errors = _reconciliation.LastErrorCount;

        if (succeededAt is null && failedAt is null)
        {
            return new HealthComponent(false, "has not completed a sweep yet");
        }

        bool healthy = errors == 0 && (failedAt is null || (succeededAt is not null && succeededAt > failedAt));
        string detail = succeededAt is null
            ? $"last failure {failedAt:o}"
            : $"last success {succeededAt:o}; last error count {errors}";
        return new HealthComponent(healthy, detail);
    }
}

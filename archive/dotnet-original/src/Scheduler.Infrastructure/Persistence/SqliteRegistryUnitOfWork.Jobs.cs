using System.Text.Json;
using Microsoft.Data.Sqlite;
using Scheduler.Application.Persistence;
using Scheduler.Contracts.Execution;
using Scheduler.Contracts.Jobs;

namespace Scheduler.Infrastructure.Persistence;

internal sealed partial class SqliteRegistryUnitOfWork
{
    private const string JobColumns =
        "job_id, plugin_id, plugin_version, enabled, schedule, parameters, config_revision, " +
        "concurrency_policy, timeout_ms, retry_policy, misfire_policy, secret_references, " +
        "execution_mode, updated_at";

    public async Task<JobRecord?> GetAsync(string jobId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(jobId);

        await using SqliteCommand command = CreateCommand(
            "SELECT " + JobColumns + " FROM jobs WHERE job_id = $jobId;");
        command.Parameters.AddWithValue("$jobId", jobId);

        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadJob(reader) : null;
    }

    public async Task<IReadOnlyList<JobRecord>> ListAsync(CancellationToken cancellationToken = default)
    {
        await using SqliteCommand command = CreateCommand(
            "SELECT " + JobColumns + " FROM jobs ORDER BY job_id;");

        List<JobRecord> jobs = [];
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            jobs.Add(ReadJob(reader));
        }

        return jobs;
    }

    public async Task<IReadOnlyList<JobRecord>> ListByPluginAsync(
        string pluginId,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pluginId);

        await using SqliteCommand command = CreateCommand(
            "SELECT " + JobColumns + " FROM jobs WHERE plugin_id = $pluginId ORDER BY job_id;");
        command.Parameters.AddWithValue("$pluginId", pluginId);

        List<JobRecord> jobs = [];
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            jobs.Add(ReadJob(reader));
        }

        return jobs;
    }

    public async Task UpsertAsync(JobRecord job, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(job);

        JobDefinition definition = job.Definition;
        await using SqliteCommand command = CreateCommand(
            """
            INSERT INTO jobs
                (job_id, plugin_id, plugin_version, enabled, schedule, parameters, config_revision,
                 concurrency_policy, timeout_ms, retry_policy, misfire_policy, secret_references,
                 execution_mode, updated_at)
            VALUES
                ($jobId, $pluginId, $pluginVersion, $enabled, $schedule, $parameters, $configRevision,
                 $concurrencyPolicy, $timeoutMs, $retryPolicy, $misfirePolicy, $secretReferences,
                 $executionMode, $updatedAt)
            ON CONFLICT(job_id) DO UPDATE SET
                plugin_id          = excluded.plugin_id,
                plugin_version     = excluded.plugin_version,
                enabled            = excluded.enabled,
                schedule           = excluded.schedule,
                parameters         = excluded.parameters,
                config_revision    = excluded.config_revision,
                concurrency_policy = excluded.concurrency_policy,
                timeout_ms         = excluded.timeout_ms,
                retry_policy       = excluded.retry_policy,
                misfire_policy     = excluded.misfire_policy,
                secret_references  = excluded.secret_references,
                execution_mode     = excluded.execution_mode,
                updated_at         = excluded.updated_at;
            """);
        command.Parameters.AddWithValue("$jobId", definition.JobId);
        command.Parameters.AddWithValue("$pluginId", definition.PluginId);
        command.Parameters.AddWithValue("$pluginVersion", definition.PluginVersion.ToString());
        command.Parameters.AddWithValue("$enabled", definition.Enabled ? 1 : 0);
        command.Parameters.AddWithValue(
            "$schedule",
            JsonSerializer.Serialize(definition.Schedule, PersistenceJson.Options));
        command.Parameters.AddWithValue(
            "$parameters",
            JsonSerializer.Serialize(definition.Parameters, PersistenceJson.Options));
        command.Parameters.AddWithValue("$configRevision", job.ConfigurationRevision);
        command.Parameters.AddWithValue("$concurrencyPolicy", definition.ConcurrencyPolicy.ToString());
        command.Parameters.AddWithValue("$timeoutMs", (long)definition.Timeout.TotalMilliseconds);
        command.Parameters.AddWithValue(
            "$retryPolicy",
            JsonSerializer.Serialize(definition.RetryPolicy, PersistenceJson.Options));
        command.Parameters.AddWithValue("$misfirePolicy", definition.MisfirePolicy.ToString());
        command.Parameters.AddWithValue(
            "$secretReferences",
            JsonSerializer.Serialize(definition.SecretReferences, PersistenceJson.Options));
        command.Parameters.AddWithValue("$executionMode", definition.ExecutionMode.ToString());
        command.Parameters.AddWithValue("$updatedAt", DbTimestamp.Format(job.UpdatedAt));

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task SetEnabledAsync(
        string jobId,
        bool enabled,
        DateTimeOffset updatedAt,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(jobId);

        await using SqliteCommand command = CreateCommand(
            "UPDATE jobs SET enabled = $enabled, updated_at = $updatedAt WHERE job_id = $jobId;");
        command.Parameters.AddWithValue("$enabled", enabled ? 1 : 0);
        command.Parameters.AddWithValue("$updatedAt", DbTimestamp.Format(updatedAt));
        command.Parameters.AddWithValue("$jobId", jobId);

        int affected = await command.ExecuteNonQueryAsync(cancellationToken);
        if (affected == 0)
        {
            throw new KeyNotFoundException($"Job '{jobId}' was not found.");
        }
    }

    public async Task<bool> DeleteAsync(string jobId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(jobId);

        await using SqliteCommand command = CreateCommand("DELETE FROM jobs WHERE job_id = $jobId;");
        command.Parameters.AddWithValue("$jobId", jobId);
        return await command.ExecuteNonQueryAsync(cancellationToken) > 0;
    }

    private static JobRecord ReadJob(SqliteDataReader reader)
    {
        JobDefinition definition = new()
        {
            JobId = reader.GetString(0),
            PluginId = reader.GetString(1),
            PluginVersion = Version.Parse(reader.GetString(2)),
            Enabled = reader.GetInt64(3) != 0,
            Schedule = Deserialize<ScheduleSpec>(reader.GetString(4)),
            Parameters = DeserializeDictionary(reader.GetString(5)),
            ConcurrencyPolicy = Enum.Parse<ConcurrencyPolicy>(reader.GetString(7)),
            Timeout = TimeSpan.FromMilliseconds(reader.GetInt64(8)),
            RetryPolicy = Deserialize<RetryPolicy>(reader.GetString(9)),
            MisfirePolicy = Enum.Parse<MisfirePolicy>(reader.GetString(10)),
            SecretReferences = Deserialize<string[]>(reader.GetString(11)),
            ExecutionMode = Enum.Parse<ExecutionMode>(reader.GetString(12)),
        };

        return new JobRecord
        {
            Definition = definition,
            ConfigurationRevision = reader.GetInt32(6),
            UpdatedAt = DbTimestamp.Parse(reader.GetString(13)),
        };
    }

    private static T Deserialize<T>(string json)
    {
        return JsonSerializer.Deserialize<T>(json, PersistenceJson.Options)
            ?? throw new InvalidOperationException("A persisted job value could not be deserialized.");
    }

    private static Dictionary<string, string?> DeserializeDictionary(string json)
    {
        return JsonSerializer.Deserialize<Dictionary<string, string?>>(json, PersistenceJson.Options)
            ?? throw new InvalidOperationException("A persisted parameters value could not be deserialized.");
    }
}

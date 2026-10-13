namespace Scheduler.Application.Persistence;

/// <summary>Persistence port for the job registry (definitions, schedules, revisions).</summary>
public interface IJobRepository
{
    Task<JobRecord?> GetAsync(string jobId, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<JobRecord>> ListAsync(CancellationToken cancellationToken = default);

    /// <summary>Lists the jobs contributed by a plugin, by stable job id.</summary>
    Task<IReadOnlyList<JobRecord>> ListByPluginAsync(string pluginId, CancellationToken cancellationToken = default);

    /// <summary>Inserts or replaces a job definition, including its configuration revision.</summary>
    Task UpsertAsync(JobRecord job, CancellationToken cancellationToken = default);

    /// <summary>Enables or disables scheduling without changing the definition revision.</summary>
    Task SetEnabledAsync(string jobId, bool enabled, DateTimeOffset updatedAt, CancellationToken cancellationToken = default);

    Task<bool> DeleteAsync(string jobId, CancellationToken cancellationToken = default);
}

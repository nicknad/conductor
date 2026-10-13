using Scheduler.Contracts.Jobs;

namespace Scheduler.Application.JobManagement;

/// <summary>
/// Authoritative job configuration use cases. Schedule and parameter changes
/// take effect without host restarts or plugin code changes.
/// </summary>
public interface IJobManager
{
    Task<IReadOnlyList<JobDefinition>> ListAsync(CancellationToken cancellationToken = default);

    Task<JobDefinition?> GetAsync(string jobId, CancellationToken cancellationToken = default);

    /// <summary>Creates or updates a job definition and bumps its configuration revision.</summary>
    Task<JobDefinition> UpdateAsync(JobDefinition definition, CancellationToken cancellationToken = default);

    Task SetEnabledAsync(string jobId, bool enabled, CancellationToken cancellationToken = default);

    /// <summary>Requests an immediate execution. Returns the new execution identifier.</summary>
    Task<Guid> RunNowAsync(string jobId, CancellationToken cancellationToken = default);
}

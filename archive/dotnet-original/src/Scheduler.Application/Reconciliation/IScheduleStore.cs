using Scheduler.Contracts.Execution;
using Scheduler.Contracts.Jobs;

namespace Scheduler.Application.Reconciliation;

/// <summary>A job that currently has a live trigger in the scheduler store.</summary>
public sealed record ScheduledJob(
    string JobId,
    string PluginId,
    string PluginVersion,
    int ConfigurationRevision);

/// <summary>The scheduling state the registry says a job should have.</summary>
public sealed record ScheduleProjection(
    string JobId,
    string PluginId,
    string PluginVersion,
    int ConfigurationRevision,
    ScheduleSpec Schedule,
    MisfirePolicy MisfirePolicy);

/// <summary>
/// The registry → Quartz projection boundary. The reconciler is the only caller;
/// no Quartz type crosses this port and every value is data-only, so the
/// application layer never depends on Quartz.
/// </summary>
public interface IScheduleStore
{
    /// <summary>Lists the jobs that currently have a live (non-paused) trigger.</summary>
    Task<IReadOnlyList<ScheduledJob>> ListAsync(CancellationToken cancellationToken = default);

    /// <summary>Creates or replaces a job's trigger so it matches <paramref name="projection" />.</summary>
    Task ApplyAsync(ScheduleProjection projection, CancellationToken cancellationToken = default);

    /// <summary>Removes a job and its trigger. A missing job is not an error.</summary>
    Task RemoveAsync(string jobId, CancellationToken cancellationToken = default);
}

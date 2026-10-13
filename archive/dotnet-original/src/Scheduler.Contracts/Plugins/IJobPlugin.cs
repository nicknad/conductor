using Scheduler.Contracts.Jobs;

namespace Scheduler.Contracts.Plugins;

/// <summary>
/// The stable, host-facing entry point of a job plugin implementation.
/// Implementations are distributed as versioned, signed packages and are
/// activated explicitly by the platform's plugin manager.
/// </summary>
public interface IJobPlugin
{
    /// <summary>Stable, unique plugin identifier.</summary>
    string Id { get; }

    /// <summary>Immutable version of this plugin implementation.</summary>
    Version Version { get; }

    /// <summary>
    /// Returns the job definitions provided by this plugin version.
    /// Definitions are data; they describe what can be scheduled, never
    /// how the host activates or dispatches the plugin.
    /// </summary>
    IReadOnlyCollection<JobDefinition> GetJobs();
}

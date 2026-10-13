using Scheduler.Application.PluginManagement;

namespace Scheduler.Application.Persistence;

/// <summary>
/// Persistence port for the plugin registry (plugin identities, versions,
/// artifact hashes, lifecycle state) and the single-row activation record.
/// </summary>
public interface IPluginRepository
{
    Task<PluginVersionRecord?> GetVersionAsync(string pluginId, Version version, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<PluginVersionRecord>> ListVersionsAsync(string pluginId, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<string>> ListPluginIdsAsync(CancellationToken cancellationToken = default);

    /// <summary>Inserts or replaces the persisted shape of a plugin version.</summary>
    Task UpsertVersionAsync(PluginVersionRecord version, CancellationToken cancellationToken = default);

    /// <summary>Updates only the lifecycle state (and validation outcome) of an existing version.</summary>
    Task SetVersionStateAsync(
        string pluginId,
        Version version,
        PluginLifecycleState state,
        string? validationError = null,
        DateTimeOffset? validatedAt = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Marks a version <see cref="PluginLifecycleState.Staged" /> after successful
    /// promotion, recording the immutable artifact path and clearing staging.
    /// </summary>
    Task SetStagedAsync(
        string pluginId,
        Version version,
        string artifactPath,
        DateTimeOffset validatedAt,
        CancellationToken cancellationToken = default);

    Task<PluginActivationRecord?> GetActivationAsync(string pluginId, CancellationToken cancellationToken = default);

    /// <summary>Atomically publishes the desired active version for a plugin.</summary>
    Task SetActivationAsync(PluginActivationRecord activation, CancellationToken cancellationToken = default);

    Task ClearActivationAsync(string pluginId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Records that a version's assembly context could not be unloaded. The
    /// version is never treated as removed while this reason is present.
    /// </summary>
    Task SetUncleanUnloadAsync(
        string pluginId,
        Version version,
        string reason,
        CancellationToken cancellationToken = default);
}

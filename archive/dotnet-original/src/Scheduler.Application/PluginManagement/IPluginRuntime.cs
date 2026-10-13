using Scheduler.Contracts.Jobs;
using Scheduler.Contracts.Plugins;

namespace Scheduler.Application.PluginManagement;

/// <summary>
/// A request to load one plugin version from its retained artifact. The entry
/// assembly is resolved inside the artifact directory; the contract assembly is
/// always shared from the host.
/// </summary>
public sealed record PluginLoadRequest(
    string PluginId,
    Version Version,
    string ArtifactDirectory,
    string EntryAssembly,
    string EntryType);

/// <summary>The jobs discovered by loading and querying a plugin version.</summary>
public sealed record LoadedPlugin(string PluginId, Version Version, IReadOnlyList<JobDefinition> Jobs);

/// <summary>
/// Outcome of an unload attempt. Unloading is cooperative: a plugin that retains
/// references keeps its context alive and is surfaced as unclean rather than
/// silently treated as removed.
/// </summary>
public sealed record PluginUnloadResult(bool Unloaded, string? Reason)
{
    public static PluginUnloadResult Clean { get; } = new(Unloaded: true, Reason: null);
}

/// <summary>
/// The execution backend boundary for plugin code. The in-process runtime loads
/// a version into its own collectible context, discovers its jobs, and resolves
/// the handler for a job. Worker backends implement the same logical contract.
/// </summary>
public interface IPluginRuntime
{
    /// <summary>Loads a plugin version and discovers its jobs. Throws on failure.</summary>
    Task<LoadedPlugin> LoadAsync(PluginLoadRequest request, CancellationToken cancellationToken = default);

    /// <summary>Attempts cooperative unload of a loaded version.</summary>
    Task<PluginUnloadResult> UnloadAsync(string pluginId, Version version, CancellationToken cancellationToken = default);

    bool IsLoaded(string pluginId, Version version);

    /// <summary>Resolves the handler for a job, or null when it is not available.</summary>
    IJobHandler? ResolveHandler(string jobId, string pluginId, Version version);
}

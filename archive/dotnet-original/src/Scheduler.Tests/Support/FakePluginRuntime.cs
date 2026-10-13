using Scheduler.Application.PluginManagement;
using Scheduler.Contracts.Plugins;

namespace Scheduler.Tests.Support;

/// <summary>
/// A runtime stub for dispatcher tests: it reports a single scripted handler
/// for every job so admission, timeout, cancellation, and retry can be tested
/// without loading real assemblies.
/// </summary>
internal sealed class FakePluginRuntime(IJobHandler? handler) : IPluginRuntime
{
    public Task<LoadedPlugin> LoadAsync(PluginLoadRequest request, CancellationToken cancellationToken = default) =>
        throw new NotSupportedException("The fake runtime does not load assemblies.");

    public Task<PluginUnloadResult> UnloadAsync(
        string pluginId,
        Version version,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(PluginUnloadResult.Clean);

    public bool IsLoaded(string pluginId, Version version) => true;

    public IJobHandler? ResolveHandler(string jobId, string pluginId, Version version) => handler;
}

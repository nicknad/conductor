using System.Reflection;
using System.Runtime.CompilerServices;
using Scheduler.Application.PluginManagement;
using Scheduler.Contracts.Jobs;
using Scheduler.Contracts.Plugins;

namespace Scheduler.Runtime.InProcess.AssemblyLoading;

/// <summary>
/// Loads plugin versions into collectible <see cref="PluginLoadContext" />s,
/// discovers their jobs, and resolves handlers. The contract assembly is always
/// the host's; plugins never carry their own copy. Unloading is cooperative and
/// surfaced as unclean when a context is still referenced.
/// </summary>
public sealed class InProcessPluginRuntime : IPluginRuntime
{
    private readonly object _lock = new();
    private readonly Dictionary<string, LoadedHandle> _loaded = new(StringComparer.Ordinal);

    public Task<LoadedPlugin> LoadAsync(PluginLoadRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        string key = Key(request.PluginId, request.Version);
        lock (_lock)
        {
            if (_loaded.TryGetValue(key, out LoadedHandle? existing))
            {
                return Task.FromResult(new LoadedPlugin(existing.PluginId, existing.Version, existing.Jobs));
            }
        }

        string entryAssemblyPath = Path.Combine(request.ArtifactDirectory, request.EntryAssembly);
        if (!File.Exists(entryAssemblyPath))
        {
            throw new FileNotFoundException(
                $"Entry assembly '{request.EntryAssembly}' was not found in the artifact.",
                entryAssemblyPath);
        }

        PluginLoadContext context = new(
            request.PluginId,
            request.Version,
            entryAssemblyPath,
            typeof(IJobPlugin).Assembly);

        try
        {
            LoadedHandle handle = BuildHandle(request, context, entryAssemblyPath);
            lock (_lock)
            {
                if (!_loaded.TryAdd(key, handle))
                {
                    context.Unload();
                    throw new InvalidOperationException(
                        $"Plugin '{request.PluginId}' '{request.Version}' is already loaded.");
                }
            }

            return Task.FromResult(new LoadedPlugin(handle.PluginId, handle.Version, handle.Jobs));
        }
        catch
        {
            context.Unload();
            throw;
        }
    }

    public async Task<PluginUnloadResult> UnloadAsync(
        string pluginId,
        Version version,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pluginId);
        ArgumentNullException.ThrowIfNull(version);
        cancellationToken.ThrowIfCancellationRequested();

        LoadedHandle? handle;
        lock (_lock)
        {
            if (!_loaded.Remove(Key(pluginId, version), out handle))
            {
                return PluginUnloadResult.Clean;
            }
        }

        WeakReference reference = DetachAndUnload(handle);
        handle = null;

        for (int attempt = 0; attempt < 10 && reference.IsAlive; attempt++)
        {
            await Task.Yield();
            GC.Collect();
            GC.WaitForPendingFinalizers();
        }

        return reference.IsAlive
            ? new PluginUnloadResult(
                Unloaded: false,
                Reason: "AssemblyLoadContext is still referenced; unload is cooperative.")
            : PluginUnloadResult.Clean;
    }

    public bool IsLoaded(string pluginId, Version version)
    {
        lock (_lock)
        {
            return _loaded.ContainsKey(Key(pluginId, version));
        }
    }

    public IJobHandler? ResolveHandler(string jobId, string pluginId, Version version)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(jobId);

        lock (_lock)
        {
            return _loaded.TryGetValue(Key(pluginId, version), out LoadedHandle? handle)
                && handle.Handlers.TryGetValue(jobId, out IJobHandler? handler)
                    ? handler
                    : null;
        }
    }

    private static LoadedHandle BuildHandle(
        PluginLoadRequest request,
        PluginLoadContext context,
        string entryAssemblyPath)
    {
        Assembly assembly = context.LoadFromAssemblyPath(entryAssemblyPath);

        Type entryType = assembly.GetType(request.EntryType, throwOnError: false)
            ?? throw new InvalidOperationException(
                $"Entry type '{request.EntryType}' was not found in '{request.EntryAssembly}'.");

        if (!typeof(IJobPlugin).IsAssignableFrom(entryType))
        {
            throw new InvalidOperationException(
                $"Entry type '{request.EntryType}' does not implement IJobPlugin.");
        }

        if (Activator.CreateInstance(entryType) is not IJobPlugin plugin)
        {
            throw new InvalidOperationException(
                $"Entry type '{request.EntryType}' could not be instantiated as IJobPlugin.");
        }

        if (!string.Equals(plugin.Id, request.PluginId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"Plugin reports id '{plugin.Id}' but was activated as '{request.PluginId}'.");
        }

        if (plugin.Version != request.Version)
        {
            throw new InvalidOperationException(
                $"Plugin reports version '{plugin.Version}' but was activated as '{request.Version}'.");
        }

        List<JobDefinition> jobs = plugin.GetJobs().ToList();
        Dictionary<string, IJobHandler> handlers = ResolveHandlers(plugin, jobs);
        return new LoadedHandle(context, plugin.Id, plugin.Version, jobs, handlers);
    }

    private static Dictionary<string, IJobHandler> ResolveHandlers(
        IJobPlugin plugin,
        IReadOnlyList<JobDefinition> jobs)
    {
        Dictionary<string, IJobHandler> handlers = new(StringComparer.Ordinal);

        foreach (JobDefinition job in jobs)
        {
            IJobHandler handler = plugin switch
            {
                IJobHandlerFactory factory => factory.CreateHandler(job.JobId),
                IJobHandler single => single,
                _ => throw new InvalidOperationException(
                    $"Plugin '{plugin.Id}' does not provide a handler for job '{job.JobId}'."),
            };

            if (!handlers.TryAdd(job.JobId, handler))
            {
                throw new InvalidOperationException(
                    $"Plugin '{plugin.Id}' declares duplicate job id '{job.JobId}'.");
            }
        }

        return handlers;
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static WeakReference DetachAndUnload(LoadedHandle handle)
    {
        PluginLoadContext context = handle.TakeContext();
        WeakReference reference = new(context);
        context.Unload();
        return reference;
    }

    private static string Key(string pluginId, Version version) => $"{pluginId}:{version}";

    private sealed class LoadedHandle(
        PluginLoadContext context,
        string pluginId,
        Version version,
        IReadOnlyList<JobDefinition> jobs,
        IReadOnlyDictionary<string, IJobHandler> handlers)
    {
        private PluginLoadContext? _context = context;

        public string PluginId { get; } = pluginId;

        public Version Version { get; } = version;

        public IReadOnlyList<JobDefinition> Jobs { get; } = jobs;

        public IReadOnlyDictionary<string, IJobHandler> Handlers { get; } = handlers;

        public PluginLoadContext TakeContext()
        {
            PluginLoadContext current = _context
                ?? throw new InvalidOperationException("The load context has already been taken.");
            _context = null;
            return current;
        }
    }
}

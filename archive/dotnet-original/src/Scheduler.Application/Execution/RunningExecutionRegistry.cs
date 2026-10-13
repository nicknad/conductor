namespace Scheduler.Application.Execution;

/// <summary>
/// A handle to one admitted, currently-running execution. Disposing the handle
/// removes it from the registry; the owning registry disposes the underlying
/// cancellation source.
/// </summary>
public interface IRunningExecution : IDisposable
{
    Guid ExecutionId { get; }

    string PluginId { get; }

    Version PluginVersion { get; }

    /// <summary>Token cancelled when cancellation is requested for this execution.</summary>
    CancellationToken Token { get; }

    /// <summary>Reason supplied when cancellation was requested, if any.</summary>
    string? CancellationReason { get; }

    void Cancel(string reason);
}

/// <summary>
/// Tracks admitted executions so cancellation and drain can find them. It is
/// the dispatch-side projection of in-flight work; durable history lives in the
/// execution store.
/// </summary>
public interface IRunningExecutionRegistry
{
    IRunningExecution Register(
        Guid executionId,
        string pluginId,
        Version pluginVersion,
        CancellationToken cancellationToken);

    bool TryCancel(Guid executionId, string reason);

    IReadOnlyList<IRunningExecution> ListForPlugin(string pluginId, Version? version = null);

    /// <summary>All currently-running executions, across plugins.</summary>
    IReadOnlyList<IRunningExecution> ListAll();

    /// <summary>Waits until no execution of the plugin version is running, or the timeout elapses.</summary>
    Task WaitForPluginAsync(
        string pluginId,
        Version version,
        TimeSpan timeout,
        CancellationToken cancellationToken = default);

    /// <summary>Waits until all executions finish, or the timeout elapses; returns whether it drained.</summary>
    Task<bool> WaitForAllAsync(TimeSpan timeout, CancellationToken cancellationToken = default);
}

/// <summary>Thread-safe in-memory registry of running executions.</summary>
public sealed class RunningExecutionRegistry : IRunningExecutionRegistry
{
    private readonly object _lock = new();
    private readonly Dictionary<Guid, Entry> _entries = [];
    private readonly TimeProvider _timeProvider;

    public RunningExecutionRegistry(TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        _timeProvider = timeProvider;
    }

    public IRunningExecution Register(
        Guid executionId,
        string pluginId,
        Version pluginVersion,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pluginId);
        ArgumentNullException.ThrowIfNull(pluginVersion);

        Entry entry = new(
            executionId,
            pluginId,
            pluginVersion,
            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken),
            Remove);

        lock (_lock)
        {
            _entries.Add(executionId, entry);
        }

        return entry;
    }

    public bool TryCancel(Guid executionId, string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);

        Entry? entry;
        lock (_lock)
        {
            _entries.TryGetValue(executionId, out entry);
        }

        if (entry is null)
        {
            return false;
        }

        entry.Cancel(reason);
        return true;
    }

    public IReadOnlyList<IRunningExecution> ListForPlugin(string pluginId, Version? version = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pluginId);

        lock (_lock)
        {
            return _entries.Values
                .Where(entry => string.Equals(entry.PluginId, pluginId, StringComparison.Ordinal)
                    && (version is null || entry.PluginVersion == version))
                .Cast<IRunningExecution>()
                .ToList();
        }
    }

    public IReadOnlyList<IRunningExecution> ListAll()
    {
        lock (_lock)
        {
            return _entries.Values.Cast<IRunningExecution>().ToList();
        }
    }

    public async Task WaitForPluginAsync(
        string pluginId,
        Version version,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        long start = _timeProvider.GetTimestamp();
        while (ListForPlugin(pluginId, version).Count > 0)
        {
            if (_timeProvider.GetElapsedTime(start) >= timeout)
            {
                return;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(10), cancellationToken);
        }
    }

    public async Task<bool> WaitForAllAsync(TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        long start = _timeProvider.GetTimestamp();
        while (Count() > 0)
        {
            if (_timeProvider.GetElapsedTime(start) >= timeout)
            {
                return false;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(10), cancellationToken);
        }

        return true;
    }

    private int Count()
    {
        lock (_lock)
        {
            return _entries.Count;
        }
    }

    private void Remove(Guid executionId)
    {
        lock (_lock)
        {
            _entries.Remove(executionId);
        }
    }

    private sealed class Entry : IRunningExecution
    {
        private readonly CancellationTokenSource _cancellation;
        private readonly Action<Guid> _onDisposed;
        private readonly object _sync = new();
        private string? _reason;
        private bool _disposed;

        public Entry(
            Guid executionId,
            string pluginId,
            Version pluginVersion,
            CancellationTokenSource cancellation,
            Action<Guid> onDisposed)
        {
            ExecutionId = executionId;
            PluginId = pluginId;
            PluginVersion = pluginVersion;
            _cancellation = cancellation;
            _onDisposed = onDisposed;
        }

        public Guid ExecutionId { get; }

        public string PluginId { get; }

        public Version PluginVersion { get; }

        public CancellationToken Token => _cancellation.Token;

        public string? CancellationReason => _reason;

        public void Cancel(string reason)
        {
            lock (_sync)
            {
                if (_disposed)
                {
                    return;
                }

                _reason = reason;
                _cancellation.Cancel();
            }
        }

        public void Dispose()
        {
            lock (_sync)
            {
                _disposed = true;
            }

            _onDisposed(ExecutionId);
            _cancellation.Dispose();
        }
    }
}

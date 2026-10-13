namespace Scheduler.Application.Execution;

/// <summary>
/// Set once the host begins shutting down so the dispatcher stops admitting new
/// fire times before the drain runs.
/// </summary>
public sealed class ShutdownSignal
{
    private volatile bool _shuttingDown;

    public bool IsShuttingDown => _shuttingDown;

    public void BeginShutdown() => _shuttingDown = true;
}

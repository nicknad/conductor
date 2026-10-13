using Scheduler.Application.Execution;

namespace Scheduler.Host;

/// <summary>
/// On shutdown: stop admitting new fire times, then apply the configured drain
/// policy to running executions before the host exits. The drain itself is
/// <see cref="ExecutionDrainer" />; this service only adds the shutdown signal
/// and logging.
/// </summary>
internal sealed class ShutdownDrainService : IHostedService
{
    private readonly ExecutionDrainer _drainer;
    private readonly IRunningExecutionRegistry _running;
    private readonly ExecutionOptions _options;
    private readonly ShutdownSignal _shutdown;
    private readonly ILogger<ShutdownDrainService> _logger;

    public ShutdownDrainService(
        ExecutionDrainer drainer,
        IRunningExecutionRegistry running,
        ExecutionOptions options,
        ShutdownSignal shutdown,
        ILogger<ShutdownDrainService> logger)
    {
        ArgumentNullException.ThrowIfNull(drainer);
        ArgumentNullException.ThrowIfNull(running);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(shutdown);
        ArgumentNullException.ThrowIfNull(logger);

        _drainer = drainer;
        _running = running;
        _options = options;
        _shutdown = shutdown;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        _shutdown.BeginShutdown();

        int running = _running.ListAll().Count;
        string policy = _options.DrainPolicy.ToString();
        HostLog.ShutdownDrainStarted(_logger, running, policy);

        bool drained = await _drainer.DrainAsync(cancellationToken);
        int remaining = _running.ListAll().Count;
        HostLog.ShutdownDrainFinished(_logger, drained, remaining);
    }
}

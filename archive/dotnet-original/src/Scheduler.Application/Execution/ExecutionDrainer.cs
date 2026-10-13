namespace Scheduler.Application.Execution;

/// <summary>
/// Applies the configured drain policy to running executions on shutdown. Under
/// <see cref="DrainPolicy.Wait" /> it waits up to the drain timeout; under
/// <see cref="DrainPolicy.Cancel" /> it cooperatively cancels running executions
/// first. It changes no durable state: an execution writes its own terminal
/// record, and an interrupted lifecycle drain re-enters from the operation
/// record on the next startup reconcile.
/// </summary>
public sealed class ExecutionDrainer
{
    private readonly IRunningExecutionRegistry _running;
    private readonly ExecutionOptions _options;

    public ExecutionDrainer(IRunningExecutionRegistry running, ExecutionOptions options)
    {
        ArgumentNullException.ThrowIfNull(running);
        ArgumentNullException.ThrowIfNull(options);

        _running = running;
        _options = options;
    }

    /// <summary>Returns whether all running executions drained within the timeout.</summary>
    public async Task<bool> DrainAsync(CancellationToken cancellationToken = default)
    {
        IReadOnlyList<IRunningExecution> running = _running.ListAll();
        if (running.Count == 0)
        {
            return true;
        }

        if (_options.DrainPolicy == DrainPolicy.Cancel)
        {
            foreach (IRunningExecution execution in running)
            {
                execution.Cancel("The host is shutting down.");
            }
        }

        try
        {
            return await _running.WaitForAllAsync(_options.DrainTimeout, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }
}

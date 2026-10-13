using Scheduler.Application.Execution;
using Scheduler.Application.Observability;
using Scheduler.Contracts.Execution;

namespace Scheduler.Runtime.InProcess.Execution;

/// <summary>
/// Builds the execution scope from a platform invocation and calls the handler
/// directly. It never exposes scheduler internals; the handler sees only
/// <see cref="JobExecutionContext" />, which is a contract type. The execution
/// logger and progress reporter are created per execution from the factory, and
/// the secret provider is supplied by the runner (once per execution) so the
/// singleton backend never carries per-execution state.
/// </summary>
public sealed class InProcessExecutionBackend : IExecutionBackend
{
    private readonly IExecutionLoggerFactory _loggerFactory;

    public InProcessExecutionBackend(IExecutionLoggerFactory loggerFactory)
    {
        ArgumentNullException.ThrowIfNull(loggerFactory);
        _loggerFactory = loggerFactory;
    }

    public ExecutionMode Mode => ExecutionMode.InProcess;

    public Task<JobResult> ExecuteAsync(ExecutionInvocation invocation, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(invocation);

        ExecutionIdentity identity = new(
            invocation.ExecutionId,
            invocation.CorrelationId,
            invocation.JobId,
            invocation.PluginId,
            invocation.PluginVersion);

        JobExecutionContext context = new(
            invocation.ExecutionId,
            invocation.JobId,
            invocation.PluginId,
            invocation.PluginVersion,
            invocation.ConfigurationRevision,
            invocation.ScheduledAt,
            invocation.Deadline,
            invocation.CorrelationId,
            invocation.Parameters,
            _loggerFactory.CreateLogger(identity),
            _loggerFactory.CreateProgressReporter(identity),
            invocation.Secrets);

        return invocation.Handler.ExecuteAsync(context, cancellationToken);
    }
}

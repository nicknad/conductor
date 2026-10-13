using Scheduler.Contracts.Execution;
using Scheduler.Contracts.Plugins;

namespace Scheduler.Tests.Support;

/// <summary>An <see cref="IJobHandler" /> whose behavior is supplied by a delegate.</summary>
internal sealed class ScriptedJobHandler(
    Func<JobExecutionContext, CancellationToken, Task<JobResult>> execute) : IJobHandler
{
    public Task<JobResult> ExecuteAsync(JobExecutionContext context, CancellationToken cancellationToken) =>
        execute(context, cancellationToken);
}

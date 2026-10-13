using Scheduler.Contracts.Execution;
using Scheduler.Contracts.Jobs;
using Scheduler.Contracts.Plugins;

namespace Scheduler.Tests.TestPlugins;

/// <summary>
/// A test plugin that deliberately retains a reference from outside its load
/// context: it subscribes an instance handler to a host-owned event, so the
/// delegate keeps this assembly alive and cooperative unload cannot complete.
/// </summary>
public sealed class RetainingJobPlugin : IJobPlugin, IJobHandlerFactory
{
    public const string PluginIdValue = "retaining-plugin";

    public const string JobIdValue = "retaining-job";

    public static readonly Version PluginVersionValue = new(1, 0, 0);

    public RetainingJobPlugin()
    {
        AppDomain.CurrentDomain.ProcessExit += OnProcessExit;
    }

    public string Id => PluginIdValue;

    public Version Version => PluginVersionValue;

    public IReadOnlyCollection<JobDefinition> GetJobs() =>
    [
        new JobDefinition
        {
            JobId = JobIdValue,
            PluginId = Id,
            PluginVersion = Version,
            Schedule = ScheduleSpec.FromCron("0 0 * * *"),
        },
    ];

    public IJobHandler CreateHandler(string jobId) => new RetainingJobHandler();

    private void OnProcessExit(object? sender, EventArgs e)
    {
    }
}

public sealed class RetainingJobHandler : IJobHandler
{
    public Task<JobResult> ExecuteAsync(JobExecutionContext context, CancellationToken cancellationToken) =>
        Task.FromResult(JobResult.Succeeded());
}

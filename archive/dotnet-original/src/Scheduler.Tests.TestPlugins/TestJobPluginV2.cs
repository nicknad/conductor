using Scheduler.Contracts.Execution;
using Scheduler.Contracts.Jobs;
using Scheduler.Contracts.Plugins;

namespace Scheduler.Tests.TestPlugins;

/// <summary>A second version of <see cref="TestJobPlugin" /> for version-replacement and rollback tests.</summary>
public sealed class TestJobPluginV2 : IJobPlugin, IJobHandlerFactory
{
    public const string PluginIdValue = "test-plugin";

    public const string JobIdValue = "test-job";

    public static readonly Version PluginVersionValue = new(2, 0, 0);

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

    public IJobHandler CreateHandler(string jobId) => new TestJobHandler();
}

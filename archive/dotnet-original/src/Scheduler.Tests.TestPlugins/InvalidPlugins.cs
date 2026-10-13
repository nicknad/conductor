using Scheduler.Contracts.Jobs;
using Scheduler.Contracts.Plugins;

namespace Scheduler.Tests.TestPlugins;

/// <summary>A plugin whose discovered definition does not match its own identity.</summary>
public sealed class InvalidDefinitionJobPlugin : IJobPlugin, IJobHandlerFactory
{
    public const string PluginIdValue = "invalid-definition-plugin";

    public const string JobIdValue = "invalid-job";

    public static readonly Version PluginVersionValue = new(1, 0, 0);

    public string Id => PluginIdValue;

    public Version Version => PluginVersionValue;

    public IReadOnlyCollection<JobDefinition> GetJobs() =>
    [
        new JobDefinition
        {
            JobId = JobIdValue,
            PluginId = "some-other-plugin",
            PluginVersion = Version,
            Schedule = ScheduleSpec.FromCron("0 0 * * *"),
        },
    ];

    public IJobHandler CreateHandler(string jobId) => new TestJobHandler();
}

/// <summary>A plugin that declares a job but provides no handler for it.</summary>
public sealed class NoHandlerJobPlugin : IJobPlugin
{
    public const string PluginIdValue = "no-handler-plugin";

    public const string JobIdValue = "no-handler-job";

    public static readonly Version PluginVersionValue = new(1, 0, 0);

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
}

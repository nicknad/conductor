using Scheduler.Contracts.Execution;
using Scheduler.Contracts.Jobs;
using Scheduler.Contracts.Plugins;

namespace Scheduler.Example.Plugin;

/// <summary>
/// Example plugin entry point. It declares one scheduled job that needs the
/// <see cref="ApiKeyReference" /> secret; the platform grants the reference to
/// an execution, and only then can the handler resolve a value.
/// </summary>
/// <remarks>
/// The plugin holds no references that outlive its collectible load context, so
/// deactivation and removal unload cleanly.
/// </remarks>
public sealed class ReportingPlugin : IJobPlugin, IJobHandlerFactory
{
    public const string PluginId = "example-reporting";

    public const string ReportJobId = "example-report";

    public const string ApiKeyReference = "example/report-api-key";

    public static readonly Version PluginVersion = new(1, 0, 0);

    public string Id => PluginId;

    public Version Version => PluginVersion;

    public IReadOnlyCollection<JobDefinition> GetJobs() =>
    [
        new JobDefinition
        {
            JobId = ReportJobId,
            PluginId = PluginId,
            PluginVersion = PluginVersion,
            Schedule = ScheduleSpec.FromCron("0 6 * * *"),
            SecretReferences = [ApiKeyReference],
            Timeout = TimeSpan.FromMinutes(5),
        },
    ];

    public IJobHandler CreateHandler(string jobId) =>
        string.Equals(jobId, ReportJobId, StringComparison.Ordinal)
            ? new ReportJobHandler()
            : throw new ArgumentOutOfRangeException(nameof(jobId), jobId, "This plugin provides only the report job.");
}

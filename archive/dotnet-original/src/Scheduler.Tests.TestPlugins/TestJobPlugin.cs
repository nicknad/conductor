using Scheduler.Contracts.Execution;
using Scheduler.Contracts.Jobs;
using Scheduler.Contracts.Plugins;

namespace Scheduler.Tests.TestPlugins;

/// <summary>
/// A well-behaved test plugin: one job whose handler behavior is driven by the
/// job's parameters. It holds no references that outlive its load context.
/// </summary>
public sealed class TestJobPlugin : IJobPlugin, IJobHandlerFactory
{
    public const string PluginIdValue = "test-plugin";

    public const string JobIdValue = "test-job";

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

    public IJobHandler CreateHandler(string jobId) => new TestJobHandler();
}

/// <summary>
/// Handler whose behavior is selected by the <c>behavior</c> parameter:
/// <c>succeed</c> (default), <c>throw</c>, <c>throwOnce</c>, <c>sleep</c>, or
/// <c>waitForCancel</c>.
/// </summary>
public sealed class TestJobHandler : IJobHandler
{
    private int _attempts;

    public async Task<JobResult> ExecuteAsync(JobExecutionContext context, CancellationToken cancellationToken)
    {
        int attempt = Interlocked.Increment(ref _attempts);
        string behavior = context.Parameters.TryGetValue("behavior", out string? value)
            ? value ?? "succeed"
            : "succeed";

        switch (behavior)
        {
            case "throw":
                throw new InvalidOperationException("test failure");
            case "throwOnce" when attempt == 1:
                throw new InvalidOperationException("transient test failure");
            case "throwOnce":
                return JobResult.Succeeded("recovered");
            case "sleep":
                await Task.Delay(ParseInt(context, "sleepMs", 50), cancellationToken);
                return JobResult.Succeeded();
            case "waitForCancel":
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                return JobResult.Succeeded();
            default:
                return JobResult.Succeeded("ok");
        }
    }

    private static int ParseInt(JobExecutionContext context, string key, int fallback) =>
        context.Parameters.TryGetValue(key, out string? value)
            && int.TryParse(value, out int parsed)
                ? parsed
                : fallback;
}

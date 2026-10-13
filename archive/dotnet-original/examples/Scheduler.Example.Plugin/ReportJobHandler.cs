using Scheduler.Contracts.Execution;
using Scheduler.Contracts.Plugins;

namespace Scheduler.Example.Plugin;

/// <summary>
/// Resolves the granted API-key reference, derives a non-reversible digest, and
/// writes a small report. The secret value is used but never logged, persisted,
/// or returned; only its digest and length appear in the report and summary.
/// </summary>
public sealed class ReportJobHandler : IJobHandler
{
    public async Task<JobResult> ExecuteAsync(JobExecutionContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        context.Logger.Log(JobLogLevel.Information, $"report starting for job '{context.JobId}'");
        context.Progress.Report(10, "resolving-key");

        string apiKey = await context.Secrets.ResolveAsync(ReportingPlugin.ApiKeyReference, cancellationToken);
        string digest = ReportDigest.OfValue(apiKey);

        context.Logger.Log(
            JobLogLevel.Information,
            $"report key resolved (digest {digest}, {apiKey.Length} characters); value not recorded");
        context.Progress.Report(50, "key-resolved");

        if (TryReadHoldMilliseconds(context.Parameters, out int holdMilliseconds))
        {
            await Task.Delay(holdMilliseconds, cancellationToken);
        }

        string reportPath = ReportPath(context.ExecutionId);
        Directory.CreateDirectory(Path.GetDirectoryName(reportPath)!);
        await File.WriteAllTextAsync(reportPath, RenderReport(context, digest, apiKey.Length), cancellationToken);

        context.Progress.Report(100, "report-written");
        context.Logger.Log(JobLogLevel.Information, $"report written to '{reportPath}'");

        return JobResult.Succeeded($"report digest={digest} length={apiKey.Length} path={reportPath}");
    }

    private static bool TryReadHoldMilliseconds(
        IReadOnlyDictionary<string, string?> parameters,
        out int holdMilliseconds)
    {
        holdMilliseconds = 0;
        return parameters.TryGetValue("holdMs", out string? value)
            && int.TryParse(value, out holdMilliseconds)
            && holdMilliseconds > 0;
    }

    private static string ReportPath(Guid executionId) =>
        Path.Combine(Path.GetTempPath(), "scheduler-example-reports", executionId.ToString("N") + ".txt");

    private static string RenderReport(JobExecutionContext context, string digest, int length) =>
        $"job={context.JobId}{Environment.NewLine}" +
        $"execution={context.ExecutionId:D}{Environment.NewLine}" +
        $"plugin={context.PluginId}@{context.PluginVersion}{Environment.NewLine}" +
        $"key-digest={digest}{Environment.NewLine}" +
        $"key-length={length}{Environment.NewLine}";
}

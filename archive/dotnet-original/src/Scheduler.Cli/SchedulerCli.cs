using System.Globalization;
using Scheduler.Application.Maintenance;
using Scheduler.Application.Observability;
using Scheduler.Application.Persistence;
using Scheduler.Application.PluginManagement;
using Scheduler.Contracts.Execution;
using Scheduler.Contracts.Jobs;

namespace Scheduler.Cli;

/// <summary>
/// The CLI entry point. It parses arguments, calls the management API through
/// <see cref="ISchedulerApiClient" />, and prints human-readable output. Exit
/// codes: 0 = done, 1 = error, 2 = not-done (rejected/unhealthy).
/// </summary>
public static class SchedulerCli
{
    public const int ExitDone = 0;
    public const int ExitError = 1;
    public const int ExitNotDone = 2;

    public static async Task<int> RunAsync(
        string[] args,
        ISchedulerApiClient client,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken = default) =>
        await RunAsync(args, client, TextReader.Null, output, error, cancellationToken);

    public static async Task<int> RunAsync(
        string[] args,
        ISchedulerApiClient client,
        TextReader input,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);

        try
        {
            return await DispatchAsync(args, client, input, output, error, cancellationToken);
        }
        catch (SchedulerApiException exception)
        {
            error.WriteLine(Describe(exception));
            return ExitError;
        }
        catch (HttpRequestException exception)
        {
            error.WriteLine($"error: cannot reach the management API: {exception.Message}");
            return ExitError;
        }
        catch (TaskCanceledException)
        {
            error.WriteLine("error: the request timed out.");
            return ExitError;
        }
    }

    private static async Task<int> DispatchAsync(
        string[] args,
        ISchedulerApiClient client,
        TextReader input,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken)
    {
        switch (args)
        {
            case ["help"] or ["--help"] or ["-?"]:
                return Usage(output, ExitDone);

            case ["status"]:
                return await StatusAsync(client, output, window: null, cancellationToken);

            case ["status", "--window", string window]:
                return await StatusWithWindowAsync(client, output, error, window, cancellationToken);

            case ["job", "list"]:
                return await JobListAsync(client, output, cancellationToken);

            case ["job", "run", string jobId]:
                return await JobRunAsync(client, output, error, jobId, cancellationToken);

            case ["job", "history", string jobId]:
                return await JobHistoryAsync(client, output, jobId, cancellationToken);

            case ["execution", "list", ..]:
                return await ExecutionListAsync(client, output, error, args[2..], cancellationToken);

            case ["execution", "show", string executionId]:
                return await ExecutionShowAsync(client, output, error, executionId, cancellationToken);

            case ["audit", "tail", ..]:
                return await AuditTailAsync(client, output, error, args[2..], cancellationToken);

            case ["health"]:
                return await HealthAsync(client, output, cancellationToken);

            case ["plugin", "list"]:
                return await PluginListAsync(client, output, cancellationToken);

            case ["plugin", "install", string path]:
                return await PluginOperationAsync(client, output, () => client.InstallPluginAsync(path, cancellationToken), cancellationToken);

            case ["plugin", "validate", string id, string version]:
                return await PluginValidateAsync(client, output, error, id, version, cancellationToken);

            case ["plugin", "activate", string id, string version]:
                return await PluginVersionOperationAsync(client, output, error, id, version, client.ActivatePluginAsync, cancellationToken);

            case ["plugin", "deactivate", string id]:
                return await PluginOperationAsync(client, output, () => client.DeactivatePluginAsync(id, cancellationToken), cancellationToken);

            case ["plugin", "rollback", string id, string version]:
                return await PluginVersionOperationAsync(client, output, error, id, version, client.RollbackPluginAsync, cancellationToken);

            case ["plugin", "remove", string id]:
                return await PluginOperationAsync(client, output, () => client.RemovePluginAsync(id, cancellationToken), cancellationToken);

            case ["secret", "list"]:
                return await SecretListAsync(client, output, cancellationToken);

            case ["secret", "set", string reference]:
                return await SecretSetAsync(client, input, output, error, reference, cancellationToken);

            case ["secret", "remove", string reference]:
                return await SecretRemoveAsync(client, output, reference, cancellationToken);

            case ["secret", "grant", ..]:
                return await SecretGrantAsync(client, output, error, args[2..], revoke: false, cancellationToken);

            case ["secret", "revoke", ..]:
                return await SecretGrantAsync(client, output, error, args[2..], revoke: true, cancellationToken);

            case ["backup", "--to", string destination]:
                return await BackupAsync(client, output, destination, cancellationToken);

            default:
                error.WriteLine("error: unknown or invalid command.");
                Usage(error, ExitError);
                return ExitError;
        }
    }

    private static async Task<int> StatusWithWindowAsync(
        ISchedulerApiClient client,
        TextWriter output,
        TextWriter error,
        string window,
        CancellationToken cancellationToken)
    {
        if (!DurationParser.TryParse(window, out TimeSpan parsed))
        {
            error.WriteLine($"error: '{window}' is not a valid window (e.g. 90s, 30m, 24h, 7d).");
            return ExitError;
        }

        return await StatusAsync(client, output, parsed, cancellationToken);
    }

    private static async Task<int> StatusAsync(
        ISchedulerApiClient client,
        TextWriter output,
        TimeSpan? window,
        CancellationToken cancellationToken)
    {
        ExecutionSummary summary = await client.GetSummaryAsync(window, cancellationToken);

        output.WriteLine($"window since {Describe(summary.Since)} (until {Describe(summary.Until)})");
        output.WriteLine("executions:");
        output.WriteLine($"  started      {summary.Executions.Started}");
        output.WriteLine($"  succeeded    {summary.Executions.Succeeded}");
        output.WriteLine($"  failed       {summary.Executions.Failed}");
        output.WriteLine($"  timed out    {summary.Executions.TimedOut}");
        output.WriteLine($"  cancelled    {summary.Executions.Cancelled}");
        output.WriteLine($"  interrupted  {summary.Executions.Interrupted}");
        output.WriteLine($"  running now  {summary.Executions.Running}");
        output.WriteLine($"  retries      {summary.Executions.Retries}");
        output.WriteLine($"rejections:    {summary.Rejections.Total}");
        foreach (KeyValuePair<string, int> reason in summary.Rejections.ByReason.OrderBy(pair => pair.Key, StringComparer.Ordinal))
        {
            output.WriteLine($"  {reason.Key,-14} {reason.Value}");
        }

        output.WriteLine($"schedules:     fired {summary.Schedules.Fired}, missed {summary.Schedules.Missed}, skipped {summary.Schedules.Skipped}");
        output.WriteLine($"lifecycle:     succeeded {Total(summary.Lifecycle.Succeeded)}, failed {Total(summary.Lifecycle.Failed)}");
        output.WriteLine($"reconciled:    repaired {summary.Reconciliation.Repaired}, failed {summary.Reconciliation.Failed}, runs {summary.Reconciliation.Runs}");
        return ExitDone;
    }

    private static async Task<int> JobListAsync(
        ISchedulerApiClient client,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<JobDefinition> jobs = await client.ListJobsAsync(cancellationToken);
        if (jobs.Count == 0)
        {
            output.WriteLine("no jobs");
            return ExitDone;
        }

        foreach (JobDefinition job in jobs)
        {
            output.WriteLine($"{job.JobId,-24} {job.PluginId,-20} {(job.Enabled ? "enabled " : "disabled")} {Describe(job.Schedule)}");
        }

        return ExitDone;
    }

    private static async Task<int> JobRunAsync(
        ISchedulerApiClient client,
        TextWriter output,
        TextWriter error,
        string jobId,
        CancellationToken cancellationToken)
    {
        try
        {
            Guid executionId = await client.RunJobAsync(jobId, cancellationToken);
            output.WriteLine($"started execution {executionId:D}");
            return ExitDone;
        }
        catch (SchedulerApiException exception)
        {
            error.WriteLine(Describe(exception));
            return ExitNotDone;
        }
    }

    private static async Task<int> JobHistoryAsync(
        ISchedulerApiClient client,
        TextWriter output,
        string jobId,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<ExecutionRecord> executions = await client.ListExecutionsAsync(
            new ExecutionFilter { JobId = jobId, Limit = 200 },
            cancellationToken);
        PrintExecutions(output, executions);
        return ExitDone;
    }

    private static async Task<int> ExecutionListAsync(
        ISchedulerApiClient client,
        TextWriter output,
        TextWriter error,
        string[] args,
        CancellationToken cancellationToken)
    {
        ExecutionFilter filter;
        if (!TryParseStatus(args, out JobExecutionStatus? status, error)
            || !TryParseSince(args, out DateTimeOffset? since, error))
        {
            return ExitError;
        }

        filter = new ExecutionFilter
        {
            Status = status,
            Since = since,
            JobId = TryGetFlag(args, "--job", out string jobId) ? jobId : null,
            Limit = TryGetIntFlag(args, "--limit", 200),
        };

        IReadOnlyList<ExecutionRecord> executions = await client.ListExecutionsAsync(filter, cancellationToken);
        PrintExecutions(output, executions);
        return ExitDone;
    }

    private static async Task<int> ExecutionShowAsync(
        ISchedulerApiClient client,
        TextWriter output,
        TextWriter error,
        string executionId,
        CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(executionId, out Guid id))
        {
            error.WriteLine($"error: '{executionId}' is not a valid execution id.");
            return ExitError;
        }

        ExecutionRecord? execution = await client.GetExecutionAsync(id, cancellationToken);
        if (execution is null)
        {
            error.WriteLine($"error: execution '{id:D}' was not found.");
            return ExitError;
        }

        output.WriteLine($"execution    {execution.ExecutionId:D}");
        output.WriteLine($"job          {execution.JobId}");
        output.WriteLine($"plugin       {execution.PluginId} {execution.PluginVersion} (rev {execution.ConfigurationRevision})");
        output.WriteLine($"status       {execution.Status}");
        output.WriteLine($"attempt      {execution.Attempt}");
        output.WriteLine($"correlation  {execution.CorrelationId ?? "(none)"}");
        output.WriteLine($"scheduled    {Describe(execution.ScheduledAt)}");
        output.WriteLine($"started      {Describe(execution.StartedAt)}");
        output.WriteLine($"ended        {Describe(execution.EndedAt)}");
        output.WriteLine($"duration     {DescribeDuration(execution)}");
        if (execution.ResultSummary is not null)
        {
            output.WriteLine($"summary      {execution.ResultSummary}");
        }

        if (execution.CancellationReason is not null)
        {
            output.WriteLine($"cancelled    {execution.CancellationReason}");
        }

        IReadOnlyList<ExecutionLogEntry> logs = await client.GetExecutionLogsAsync(id, cancellationToken);
        output.WriteLine($"logs ({logs.Count}):");
        foreach (ExecutionLogEntry entry in logs)
        {
            output.WriteLine($"  {entry.Timestamp:o} [{entry.Level}] {entry.Message}");
        }

        return execution.Status is JobExecutionStatus.Succeeded ? ExitDone : ExitNotDone;
    }

    private static async Task<int> AuditTailAsync(
        ISchedulerApiClient client,
        TextWriter output,
        TextWriter error,
        string[] args,
        CancellationToken cancellationToken)
    {
        if (!TryParseSince(args, out DateTimeOffset? since, error))
        {
            return ExitError;
        }

        AuditFilter filter = new()
        {
            Actor = TryGetFlag(args, "--actor", out string actor) ? actor : null,
            Action = TryGetFlag(args, "--action", out string action) ? action : null,
            Target = TryGetFlag(args, "--target", out string target) ? target : null,
            Since = since,
            Limit = TryGetIntFlag(args, "--limit", 50),
        };

        IReadOnlyList<AuditEntry> entries = await client.ListAuditAsync(filter, cancellationToken);
        foreach (AuditEntry entry in entries)
        {
            string details = entry.Details is null ? string.Empty : $" — {entry.Details}";
            output.WriteLine($"{entry.Timestamp:o} {entry.Actor} {entry.Action} {entry.Target}{details}");
        }

        return ExitDone;
    }

    private static async Task<int> HealthAsync(
        ISchedulerApiClient client,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        HealthReport report = await client.GetHealthAsync(cancellationToken);
        output.WriteLine($"health       {(report.Healthy ? "healthy" : "degraded")}");
        output.WriteLine($"database     {(report.Database.Healthy ? "ok" : "down")} — {report.Database.Detail}");
        output.WriteLine($"reconciler   {(report.Reconciler.Healthy ? "ok" : "degraded")} — {report.Reconciler.Detail}");
        output.WriteLine($"stuck        {report.StuckExecutions.Count}");
        foreach (Guid id in report.StuckExecutions)
        {
            output.WriteLine($"  {id:D}");
        }

        return report.Healthy ? ExitDone : ExitNotDone;
    }

    private static async Task<int> PluginListAsync(
        ISchedulerApiClient client,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<PluginDescriptor> plugins = await client.ListPluginsAsync(cancellationToken);
        if (plugins.Count == 0)
        {
            output.WriteLine("no plugins");
            return ExitDone;
        }

        foreach (PluginDescriptor plugin in plugins)
        {
            string active = plugin.ActiveVersion is null ? "(none)" : plugin.ActiveVersion.ToString();
            output.WriteLine($"{plugin.PluginId,-24} {plugin.State,-12} active {active}");
        }

        return ExitDone;
    }

    private static async Task<int> PluginValidateAsync(
        ISchedulerApiClient client,
        TextWriter output,
        TextWriter error,
        string id,
        string version,
        CancellationToken cancellationToken)
    {
        if (!Version.TryParse(version, out Version? parsed))
        {
            error.WriteLine($"error: '{version}' is not a valid version.");
            return ExitError;
        }

        ValidationReport report = await client.ValidatePluginAsync(id, parsed, cancellationToken);
        output.WriteLine($"{report.PluginId} {report.Version}: {(report.IsValid ? "valid" : "invalid")}");
        foreach (string message in report.Errors.Concat(report.Warnings))
        {
            output.WriteLine($"  {message}");
        }

        return report.IsValid ? ExitDone : ExitNotDone;
    }

    private static async Task<int> PluginVersionOperationAsync(
        ISchedulerApiClient client,
        TextWriter output,
        TextWriter error,
        string id,
        string version,
        Func<string, Version, CancellationToken, Task<PluginOperation>> operation,
        CancellationToken cancellationToken)
    {
        if (!Version.TryParse(version, out Version? parsed))
        {
            error.WriteLine($"error: '{version}' is not a valid version.");
            return ExitError;
        }

        PluginOperation result = await operation(id, parsed, cancellationToken);
        return PrintPluginOperation(output, result);
    }

    private static async Task<int> PluginOperationAsync(
        ISchedulerApiClient client,
        TextWriter output,
        Func<Task<PluginOperation>> operation,
        CancellationToken cancellationToken)
    {
        PluginOperation result = await operation();
        return PrintPluginOperation(output, result);
    }

    private static int PrintPluginOperation(TextWriter output, PluginOperation operation)
    {
        output.WriteLine($"{operation.PluginId}: {operation.Status}" + (operation.Error is null ? string.Empty : $" — {operation.Error}"));
        return operation.Status == PluginOperationStatus.Succeeded ? ExitDone : ExitNotDone;
    }

    private static async Task<int> SecretListAsync(
        ISchedulerApiClient client,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<string> references = await client.ListSecretReferencesAsync(cancellationToken);
        if (references.Count == 0)
        {
            output.WriteLine("no secrets");
            return ExitDone;
        }

        foreach (string reference in references)
        {
            output.WriteLine(reference);
        }

        return ExitDone;
    }

    private static async Task<int> SecretSetAsync(
        ISchedulerApiClient client,
        TextReader input,
        TextWriter output,
        TextWriter error,
        string reference,
        CancellationToken cancellationToken)
    {
        string? value = await input.ReadLineAsync(cancellationToken);
        if (string.IsNullOrEmpty(value))
        {
            error.WriteLine("error: provide the secret value on standard input.");
            return ExitError;
        }

        await client.SetSecretAsync(reference, value, cancellationToken);
        output.WriteLine($"secret {reference}: set");
        return ExitDone;
    }

    private static async Task<int> SecretRemoveAsync(
        ISchedulerApiClient client,
        TextWriter output,
        string reference,
        CancellationToken cancellationToken)
    {
        await client.RemoveSecretAsync(reference, cancellationToken);
        output.WriteLine($"secret {reference}: removed");
        return ExitDone;
    }

    private static async Task<int> SecretGrantAsync(
        ISchedulerApiClient client,
        TextWriter output,
        TextWriter error,
        string[] args,
        bool revoke,
        CancellationToken cancellationToken)
    {
        if (args.Length < 2)
        {
            error.WriteLine("error: secret grant/revoke requires <pluginId> <reference>.");
            return ExitError;
        }

        string pluginId = args[0];
        string reference = args[1];
        string? jobId = TryGetFlag(args, "--job", out string job) ? job : null;

        if (revoke)
        {
            bool removed = await client.RevokeSecretAsync(pluginId, jobId, reference, cancellationToken);
            output.WriteLine($"grant {pluginId}/{jobId ?? "*"} {reference}: {(removed ? "revoked" : "absent")}");
        }
        else
        {
            await client.GrantSecretAsync(pluginId, jobId, reference, cancellationToken);
            output.WriteLine($"grant {pluginId}/{jobId ?? "*"} {reference}: granted");
        }

        return ExitDone;
    }

    private static async Task<int> BackupAsync(
        ISchedulerApiClient client,
        TextWriter output,
        string destination,
        CancellationToken cancellationToken)
    {
        BackupResult result = await client.BackupAsync(destination, cancellationToken);
        output.WriteLine($"backup {result.Root}: {result.ArtifactCount} artifact(s), verified={result.Verified}");
        return result.Verified ? ExitDone : ExitNotDone;
    }

    private static void PrintExecutions(TextWriter output, IReadOnlyList<ExecutionRecord> executions)
    {
        if (executions.Count == 0)
        {
            output.WriteLine("no executions");
            return;
        }

        foreach (ExecutionRecord execution in executions)
        {
            output.WriteLine(
                $"{execution.ExecutionId:D} {execution.JobId,-20} {execution.Status,-12} " +
                $"{Describe(execution.ScheduledAt)} {DescribeDuration(execution)}");
        }
    }

    private static string Describe(SchedulerApiException exception) =>
        $"error: {exception.Message}" + (exception.Reason is null ? string.Empty : $" (reason: {exception.Reason})");

    private static string Describe(ScheduleSpec schedule) =>
        schedule.Cron is not null ? $"cron {schedule.Cron}"
        : schedule.Interval is not null ? $"every {schedule.Interval}"
        : schedule.OneShotAt is not null ? $"once {schedule.OneShotAt:o}"
        : "unscheduled";

    private static string Describe(DateTimeOffset? value) =>
        value?.ToString("o", CultureInfo.InvariantCulture) ?? "-";

    private static string DescribeDuration(ExecutionRecord execution) =>
        execution.StartedAt is { } started && execution.EndedAt is { } ended
            ? (ended - started).ToString("c", CultureInfo.InvariantCulture)
            : "-";

    private static string Describe(DateTimeOffset value) => value.ToString("o", CultureInfo.InvariantCulture);

    private static int Total(IReadOnlyDictionary<string, int> counts) => counts.Values.Sum();

    private static bool TryGetFlag(IReadOnlyList<string> args, string name, out string value)
    {
        for (int index = 0; index < args.Count - 1; index++)
        {
            if (string.Equals(args[index], name, StringComparison.Ordinal))
            {
                value = args[index + 1];
                return true;
            }
        }

        value = string.Empty;
        return false;
    }

    private static int TryGetIntFlag(IReadOnlyList<string> args, string name, int fallback) =>
        TryGetFlag(args, name, out string value) && int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsed)
            ? parsed
            : fallback;

    private static bool TryParseStatus(IReadOnlyList<string> args, out JobExecutionStatus? status, TextWriter error)
    {
        status = null;
        if (!TryGetFlag(args, "--status", out string value))
        {
            return true;
        }

        if (!Enum.TryParse(value, ignoreCase: true, out JobExecutionStatus parsed) || !Enum.IsDefined(parsed))
        {
            error.WriteLine($"error: '{value}' is not a valid execution status.");
            return false;
        }

        status = parsed;
        return true;
    }

    private static bool TryParseSince(IReadOnlyList<string> args, out DateTimeOffset? since, TextWriter error)
    {
        since = null;
        if (!TryGetFlag(args, "--since", out string value))
        {
            return true;
        }

        if (!DurationParser.TryParse(value, out TimeSpan window))
        {
            error.WriteLine($"error: '{value}' is not a valid duration (e.g. 90s, 30m, 24h, 7d).");
            return false;
        }

        since = DateTimeOffset.UtcNow - window;
        return true;
    }

    private static int Usage(TextWriter writer, int exitCode)
    {
        writer.WriteLine(
            """
            Usage: scheduler <command> [arguments] [--api <base-url>]

            Commands:
              status [--window 24h]
              job list
              job run <id>
              job history <id>
              execution list [--status <status>] [--since 24h] [--job <id>] [--limit n]
              execution show <id>
              audit tail [--actor <a>] [--action <a>] [--target <t>] [--since 24h] [--limit n]
              health
              plugin list
              plugin install <package-path>
              plugin validate <id> <version>
              plugin activate <id> <version>
              plugin deactivate <id>
              plugin rollback <id> <version>
              plugin remove <id>
              secret list
              secret set <reference>            (value read from standard input)
              secret remove <reference>
              secret grant <pluginId> <reference> [--job <id>]
              secret revoke <pluginId> <reference> [--job <id>]
              backup --to <destination>
            """);
        return exitCode;
    }
}

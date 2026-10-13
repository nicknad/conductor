using Scheduler.Contracts.Secrets;

namespace Scheduler.Contracts.Execution;

/// <summary>
/// The execution context handed to an <c>IJobHandler</c>. It is constructed
/// by the host, carries only stable platform abstractions, and never exposes
/// scheduler internals such as Quartz types.
/// </summary>
public sealed class JobExecutionContext
{
    private readonly IJobExecutionLogger _logger;
    private readonly IJobProgressReporter _progress;
    private readonly ISecretProvider _secrets;

    public JobExecutionContext(
        Guid executionId,
        string jobId,
        string pluginId,
        Version pluginVersion,
        int configurationRevision,
        DateTimeOffset scheduledAt,
        DateTimeOffset deadline,
        string correlationId,
        IReadOnlyDictionary<string, string?> parameters,
        IJobExecutionLogger logger,
        IJobProgressReporter progress,
        ISecretProvider secrets)
    {
        ExecutionId = executionId;
        JobId = jobId;
        PluginId = pluginId;
        PluginVersion = pluginVersion;
        ConfigurationRevision = configurationRevision;
        ScheduledAt = scheduledAt;
        Deadline = deadline;
        CorrelationId = correlationId;
        Parameters = parameters;
        _logger = logger;
        _progress = progress;
        _secrets = secrets;
    }

    /// <summary>Unique identifier of this execution attempt.</summary>
    public Guid ExecutionId { get; }

    public string JobId { get; }

    public string PluginId { get; }

    public Version PluginVersion { get; }

    /// <summary>Configuration revision this execution was started with.</summary>
    public int ConfigurationRevision { get; }

    public DateTimeOffset ScheduledAt { get; }

    /// <summary>Latest point in time this execution may still be running.</summary>
    public DateTimeOffset Deadline { get; }

    /// <summary>Correlation identifier that links logs, metrics, and audit events.</summary>
    public string CorrelationId { get; }

    /// <summary>Validated parameters for this execution (data only).</summary>
    public IReadOnlyDictionary<string, string?> Parameters { get; }

    public IJobExecutionLogger Logger => _logger;

    public IJobProgressReporter Progress => _progress;

    /// <summary>
    /// Secret provider restricted to the references granted to this job by
    /// platform policy. It is an authorization boundary, not a sandbox.
    /// </summary>
    public ISecretProvider Secrets => _secrets;
}

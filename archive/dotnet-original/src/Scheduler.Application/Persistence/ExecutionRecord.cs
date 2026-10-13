using Scheduler.Contracts.Execution;

namespace Scheduler.Application.Persistence;

/// <summary>
/// Durable record of one execution attempt. Each execution pins the plugin
/// version and configuration revision it was dispatched with.
/// </summary>
public sealed record ExecutionRecord
{
    public required Guid ExecutionId { get; init; }

    public required string JobId { get; init; }

    public required string PluginId { get; init; }

    public required Version PluginVersion { get; init; }

    public required int ConfigurationRevision { get; init; }

    /// <summary>One-based attempt number within the job's retry policy.</summary>
    public required int Attempt { get; init; }

    public required JobExecutionStatus Status { get; init; }

    /// <summary>
    /// Correlation id generated at dispatch; links execution history, the
    /// per-execution log, and audit events. Null for rows written before the
    /// column existed.
    /// </summary>
    public string? CorrelationId { get; init; }

    public required DateTimeOffset ScheduledAt { get; init; }

    public DateTimeOffset? StartedAt { get; init; }

    public DateTimeOffset? EndedAt { get; init; }

    /// <summary>Sanitized result summary; never contains secret values.</summary>
    public string? ResultSummary { get; init; }

    public string? CancellationReason { get; init; }
}

using Scheduler.Contracts.Execution;

namespace Scheduler.Application.Observability;

/// <summary>Filters for an execution-history query. All members are optional.</summary>
public sealed record ExecutionFilter
{
    public string? JobId { get; init; }

    public JobExecutionStatus? Status { get; init; }

    public DateTimeOffset? Since { get; init; }

    public DateTimeOffset? Until { get; init; }

    /// <summary>Maximum number of rows; clamped to <see cref="ObservabilityOptions.ExecutionListLimit" /> by the caller.</summary>
    public int Limit { get; init; } = 100;
}

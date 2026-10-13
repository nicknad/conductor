namespace Scheduler.Application.Observability;

/// <summary>
/// Operator-facing observability tuning. These values only shape reads and
/// retention; none of them change scheduling behavior.
/// </summary>
public sealed class ObservabilityOptions
{
    /// <summary>Default window for the executions summary when the caller does not supply one.</summary>
    public TimeSpan SummaryWindow { get; init; } = TimeSpan.FromHours(24);

    /// <summary>
    /// A <c>Running</c> execution older than this is reported as stuck by the
    /// health detail endpoint. There is no heartbeat column; the threshold is
    /// measured from <c>started_at</c>.
    /// </summary>
    public TimeSpan ExecutionHeartbeat { get; init; } = TimeSpan.FromMinutes(30);

    /// <summary>How often the stuck-execution monitor re-checks the heartbeat threshold.</summary>
    public TimeSpan StuckCheckInterval { get; init; } = TimeSpan.FromMinutes(1);

    /// <summary>Maximum number of executions returned by a single history query.</summary>
    public int ExecutionListLimit { get; init; } = 200;

    /// <summary>Number of most-recent per-execution log files retained at startup.</summary>
    public int RetainedLogs { get; init; } = 500;
}

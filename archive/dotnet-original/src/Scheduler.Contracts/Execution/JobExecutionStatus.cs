namespace Scheduler.Contracts.Execution;

public enum JobExecutionStatus
{
    Pending,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    TimedOut,

    /// <summary>The host terminated while the execution was running. Requires
    /// explicit recovery classification before any retry.</summary>
    Interrupted,
}

namespace Scheduler.Contracts.Execution;

/// <summary>Whether overlapping executions of the same job are permitted.</summary>
public enum ConcurrencyPolicy
{
    /// <summary>Default. A new execution cannot start while another is running.</summary>
    DisallowOverlap,

    /// <summary>Explicit opt-in. Overlapping executions are allowed up to the job's and global limits.</summary>
    AllowParallel,
}

/// <summary>Behavior when a scheduled fire time is missed.</summary>
public enum MisfirePolicy
{
    /// <summary>Run once as soon as possible, then resume the schedule.</summary>
    FireOnce,

    /// <summary>Skip the missed fire time and wait for the next one.</summary>
    Skip,

    /// <summary>Run immediately, abandoning the original fire time.</summary>
    RunImmediately,
}

/// <summary>How a job executes.</summary>
public enum ExecutionMode
{
    InProcess,
    Worker,
}

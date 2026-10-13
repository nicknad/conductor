namespace Scheduler.Contracts.Execution;

/// <summary>
/// Structured progress reporting for long-running executions. The host decides
/// what happens with progress (logs, metrics, API exposure); plugins only report.
/// </summary>
public interface IJobProgressReporter
{
    /// <summary>Reports progress within [0, 100] and a free-form stage label.</summary>
    void Report(int percent, string? stage = null);
}

/// <summary>Minimal, host-supplied logging abstraction so the contract assembly stays dependency-free.</summary>
public interface IJobExecutionLogger
{
    void Log(JobLogLevel level, string message, Exception? exception = null);
}

public enum JobLogLevel
{
    Trace,
    Debug,
    Information,
    Warning,
    Error,
}

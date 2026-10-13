namespace Scheduler.Application.Observability;

/// <summary>One captured per-execution log line. Message and exception are already sanitized.</summary>
public sealed record ExecutionLogEntry(
    DateTimeOffset Timestamp,
    string Level,
    string Message,
    string? Exception);

/// <summary>
/// Persists plugin log output per execution and reads it back for the operations
/// surface. File-backed today; the port keeps the transport out of the application.
/// </summary>
public interface IExecutionLogStore
{
    /// <summary>Appends one entry. Synchronous because the plugin logger contract is synchronous.</summary>
    void Append(Guid executionId, ExecutionLogEntry entry);

    Task<IReadOnlyList<ExecutionLogEntry>> ReadAsync(Guid executionId, CancellationToken cancellationToken = default);

    /// <summary>Deletes per-execution log files beyond the retention count. Idempotent.</summary>
    Task TrimAsync(int retained, CancellationToken cancellationToken = default);
}

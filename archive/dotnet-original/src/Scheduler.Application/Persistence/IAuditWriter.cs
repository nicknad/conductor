namespace Scheduler.Application.Persistence;

/// <summary>
/// Records audit events. The timestamp comes from the host clock, so callers
/// supply only the actor, action, and target — never the time.
/// </summary>
public interface IAuditWriter
{
    Task RecordAsync(
        string actor,
        string action,
        string target,
        string? details = null,
        CancellationToken cancellationToken = default);
}

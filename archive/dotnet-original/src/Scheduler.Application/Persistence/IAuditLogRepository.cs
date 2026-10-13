using Scheduler.Application.Observability;

namespace Scheduler.Application.Persistence;

/// <summary>Persistence port for the audit log. Values are never secrets.</summary>
public interface IAuditLogRepository
{
    Task WriteAsync(AuditEntry entry, CancellationToken cancellationToken = default);

    /// <summary>Returns the most recent entries, newest first.</summary>
    Task<IReadOnlyList<AuditEntry>> ListAsync(int limit = 100, CancellationToken cancellationToken = default);

    /// <summary>Returns the most recent entries matching <paramref name="filter" />, newest first.</summary>
    Task<IReadOnlyList<AuditEntry>> ListAsync(AuditFilter filter, CancellationToken cancellationToken = default);
}

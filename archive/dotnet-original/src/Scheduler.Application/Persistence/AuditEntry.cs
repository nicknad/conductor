namespace Scheduler.Application.Persistence;

/// <summary>One audit-log event: who performed which action, on what, and when.</summary>
public sealed record AuditEntry
{
    /// <summary>Storage-assigned identifier; zero until persisted.</summary>
    public long Id { get; init; }

    public required DateTimeOffset Timestamp { get; init; }

    public required string Actor { get; init; }

    public required string Action { get; init; }

    public required string Target { get; init; }

    public string? Details { get; init; }
}

namespace Scheduler.Application.Observability;

/// <summary>Filters for an audit-log query. All members are optional.</summary>
public sealed record AuditFilter
{
    public string? Actor { get; init; }

    public string? Action { get; init; }

    public string? Target { get; init; }

    public DateTimeOffset? Since { get; init; }

    public int Limit { get; init; } = 100;
}

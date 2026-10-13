namespace Scheduler.Application.Observability;

/// <summary>A single component's health for the operational health detail endpoint.</summary>
public sealed record HealthComponent(bool Healthy, string Detail);

/// <summary>
/// Operational health detail (distinct from the liveness probe): database
/// reachability, reconciler last success/errors, and executions that look stuck.
/// </summary>
public sealed record HealthReport(
    bool Healthy,
    DateTimeOffset CheckedAt,
    HealthComponent Database,
    HealthComponent Reconciler,
    IReadOnlyList<Guid> StuckExecutions);

public interface IHealthReportService
{
    Task<HealthReport> GetHealthAsync(CancellationToken cancellationToken = default);
}

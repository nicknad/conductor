using Scheduler.Contracts.Execution;

namespace Scheduler.Application.Observability;

/// <summary>What happened to a scheduled fire.</summary>
public enum ScheduleEventKind
{
    Fired,
    Missed,
    Skipped,
}

/// <summary>A durable record of a scheduled fire, misfire, or skip.</summary>
public sealed record ScheduleEvent
{
    public long Id { get; init; }

    public required DateTimeOffset Timestamp { get; init; }

    public required string JobId { get; init; }

    public required ScheduleEventKind Kind { get; init; }

    /// <summary>The job's misfire policy at the time of a miss, when it could be resolved.</summary>
    public MisfirePolicy? MisfirePolicy { get; init; }
}

public sealed record ScheduleEventCounts(int Fired, int Missed, int Skipped);

/// <summary>Persistence port for durable schedule-fire events.</summary>
public interface IScheduleEventRepository
{
    Task RecordAsync(ScheduleEvent scheduleEvent, CancellationToken cancellationToken = default);

    Task<ScheduleEventCounts> CountAsync(DateTimeOffset? since, CancellationToken cancellationToken = default);
}

/// <summary>Records fired/missed/skipped schedule events observed from Quartz.</summary>
public interface IScheduleEventRecorder
{
    Task RecordFiredAsync(string jobId, CancellationToken cancellationToken = default);

    Task RecordMisfiredAsync(string jobId, CancellationToken cancellationToken = default);

    Task RecordSkippedAsync(string jobId, CancellationToken cancellationToken = default);
}

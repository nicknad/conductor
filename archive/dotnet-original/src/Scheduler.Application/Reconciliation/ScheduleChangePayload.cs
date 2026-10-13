using Scheduler.Application.Persistence;
using Scheduler.Contracts.Execution;
using Scheduler.Contracts.Jobs;

namespace Scheduler.Application.Reconciliation;

/// <summary>The registry → Quartz change an outbox record describes.</summary>
public enum ScheduleChangeAction
{
    Create,
    Update,
    Pause,
    Delete,
}

/// <summary>
/// Serialized, versioned payload of an <see cref="OperationKind.ScheduleChange" />
/// outbox record. It carries the desired scheduling state so the reconciler can
/// apply the change idempotently, but the registry remains authoritative: the
/// reconciler re-reads the job before applying.
/// </summary>
public sealed record ScheduleChangePayload
{
    public const int CurrentVersion = 1;

    public int PayloadVersion { get; init; } = CurrentVersion;

    public required string JobId { get; init; }

    public required ScheduleChangeAction Action { get; init; }

    public string? PluginId { get; init; }

    public string? PluginVersion { get; init; }

    public int ConfigurationRevision { get; init; }

    public bool Enabled { get; init; }

    public ScheduleSpec? Schedule { get; init; }

    public MisfirePolicy MisfirePolicy { get; init; } = MisfirePolicy.FireOnce;
}

/// <summary>Builds the durable outbox record for a job's desired schedule.</summary>
public static class ScheduleChangeOutbox
{
    public static OperationRecord Create(
        Guid operationId,
        JobRecord job,
        ScheduleChangeAction action,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(job);

        ScheduleChangePayload payload = new()
        {
            JobId = job.Definition.JobId,
            Action = action,
            PluginId = job.Definition.PluginId,
            PluginVersion = job.Definition.PluginVersion.ToString(),
            ConfigurationRevision = job.ConfigurationRevision,
            Enabled = job.Definition.Enabled,
            Schedule = job.Definition.Schedule,
            MisfirePolicy = job.Definition.MisfirePolicy,
        };

        return new OperationRecord
        {
            OperationId = operationId,
            Kind = OperationKind.ScheduleChange,
            Payload = OperationPayloadCodec.Serialize(payload),
            State = OperationState.Pending,
            CreatedAt = now,
            UpdatedAt = now,
        };
    }
}

using Scheduler.Application.Persistence;
using Scheduler.Contracts.Execution;
using Scheduler.Contracts.Jobs;

namespace Scheduler.Tests.Integration.Scheduling;

/// <summary>Shared registry fixtures for scheduling/reconciliation tests.</summary>
internal static class ScheduleTestData
{
    public static JobDefinition Definition(
        string jobId = "job-1",
        bool enabled = true,
        string pluginId = "plugin-1") => new()
        {
            JobId = jobId,
            PluginId = pluginId,
            PluginVersion = new Version(1, 0, 0),
            Enabled = enabled,
            Schedule = ScheduleSpec.FromInterval(TimeSpan.FromMinutes(5)),
            MisfirePolicy = MisfirePolicy.FireOnce,
        };

    public static JobRecord Record(JobDefinition definition, int revision = 1) => new()
    {
        Definition = definition,
        ConfigurationRevision = revision,
        UpdatedAt = DateTimeOffset.UnixEpoch,
    };

    public static OperationRecord ActivationOperation(
        string pluginId,
        string? version,
        OperationState state = OperationState.Running) => new()
        {
            OperationId = Guid.NewGuid(),
            Kind = OperationKind.Activate,
            Payload = OperationPayloadCodec.Serialize(new LifecycleOperationPayload(pluginId, version)),
            State = state,
            CreatedAt = DateTimeOffset.UnixEpoch,
            UpdatedAt = DateTimeOffset.UnixEpoch,
        };
}

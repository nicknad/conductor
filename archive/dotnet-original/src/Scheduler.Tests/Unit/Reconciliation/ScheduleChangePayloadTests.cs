using Scheduler.Application.Persistence;
using Scheduler.Application.Reconciliation;
using Scheduler.Contracts.Execution;
using Scheduler.Contracts.Jobs;

namespace Scheduler.Tests.Unit.Reconciliation;

public sealed class ScheduleChangePayloadTests
{
    [Fact]
    public void RoundTripsCronPayloadWithEnumsAndTimeSpans()
    {
        ScheduleChangePayload original = new()
        {
            JobId = "nightly",
            Action = ScheduleChangeAction.Update,
            PluginId = "reports",
            PluginVersion = "1.2.0",
            ConfigurationRevision = 7,
            Enabled = true,
            Schedule = ScheduleSpec.FromCron("0 0 2 * * ?"),
            MisfirePolicy = MisfirePolicy.Skip,
        };

        string json = OperationPayloadCodec.Serialize(original);
        ScheduleChangePayload reloaded = OperationPayloadCodec.Deserialize<ScheduleChangePayload>(json);

        Assert.Equal(original, reloaded);
        Assert.Equal(ScheduleChangePayload.CurrentVersion, reloaded.PayloadVersion);
    }

    [Fact]
    public void RoundTripsIntervalPayload()
    {
        ScheduleChangePayload original = new()
        {
            JobId = "poll",
            Action = ScheduleChangeAction.Create,
            ConfigurationRevision = 1,
            Enabled = true,
            Schedule = ScheduleSpec.FromInterval(TimeSpan.FromSeconds(30)),
            MisfirePolicy = MisfirePolicy.RunImmediately,
        };

        string json = OperationPayloadCodec.Serialize(original);
        ScheduleChangePayload reloaded = OperationPayloadCodec.Deserialize<ScheduleChangePayload>(json);

        Assert.Equal(TimeSpan.FromSeconds(30), reloaded.Schedule?.Interval);
        Assert.Equal(MisfirePolicy.RunImmediately, reloaded.MisfirePolicy);
    }

    [Fact]
    public void RoundTripsLifecyclePayload()
    {
        LifecycleOperationPayload original = new("reports", "2.0.0") { UncleanUnload = "still referenced" };

        string json = OperationPayloadCodec.Serialize(original);
        LifecycleOperationPayload reloaded = OperationPayloadCodec.Deserialize<LifecycleOperationPayload>(json);

        Assert.Equal(original, reloaded);
        Assert.Equal(LifecycleOperationPayload.CurrentVersion, reloaded.PayloadVersion);
    }
}

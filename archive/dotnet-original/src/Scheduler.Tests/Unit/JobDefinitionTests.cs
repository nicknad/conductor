using Scheduler.Contracts.Execution;
using Scheduler.Contracts.Jobs;

namespace Scheduler.Tests.Unit;

public sealed class JobDefinitionTests
{
    private static JobDefinition ValidDefinition() => new()
    {
        JobId = "monthly-report",
        PluginId = "monthly-report",
        PluginVersion = new Version(1, 2, 0),
        Schedule = ScheduleSpec.FromCron("0 0 1 * *"),
    };

    [Fact]
    public void MinimalDefinitionIsValid()
    {
        JobDefinition definition = ValidDefinition();

        Assert.Empty(definition.Validate());
    }

    [Fact]
    public void DefaultsAreNoOverlapAndInProcess()
    {
        JobDefinition definition = ValidDefinition();

        Assert.Equal(ConcurrencyPolicy.DisallowOverlap, definition.ConcurrencyPolicy);
        Assert.Equal(ExecutionMode.InProcess, definition.ExecutionMode);
        Assert.True(definition.Enabled);
    }

    [Fact]
    public void EmptyJobIdIsRejected()
    {
        JobDefinition definition = ValidDefinition() with { JobId = "" };

        Assert.Contains("JobId must not be empty.", definition.Validate(), StringComparer.Ordinal);
    }

    [Fact]
    public void NonPositiveTimeoutIsRejected()
    {
        JobDefinition definition = ValidDefinition() with { Timeout = TimeSpan.Zero };

        Assert.Contains("Timeout must be positive.", definition.Validate(), StringComparer.Ordinal);
    }

    [Fact]
    public void InvalidScheduleIsRejected()
    {
        JobDefinition definition = ValidDefinition() with { Schedule = ScheduleSpec.FromInterval(TimeSpan.Zero) };

        Assert.Contains("Interval must be positive.", definition.Validate(), StringComparer.Ordinal);
    }

    [Fact]
    public void InvalidRetryPolicyIsRejected()
    {
        JobDefinition definition = ValidDefinition() with { RetryPolicy = new RetryPolicy { MaxAttempts = 0 } };

        Assert.Contains("MaxAttempts must be at least 1.", definition.Validate(), StringComparer.Ordinal);
    }
}

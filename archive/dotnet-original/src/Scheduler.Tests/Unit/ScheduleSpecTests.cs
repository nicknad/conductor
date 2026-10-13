using Scheduler.Contracts.Jobs;

namespace Scheduler.Tests.Unit;

public sealed class ScheduleSpecTests
{
    [Fact]
    public void CronWithFiveFieldsIsValid()
    {
        ScheduleSpec spec = ScheduleSpec.FromCron("0 0 1 * *");

        Assert.Empty(spec.Validate());
    }

    [Fact]
    public void CronWithSevenFieldsIsValid()
    {
        ScheduleSpec spec = ScheduleSpec.FromCron("0 0 0 1 1 ? 2027");

        Assert.Empty(spec.Validate());
    }

    [Theory]
    [InlineData("0 0 1")]
    [InlineData("0 0 1 * * * * *")]
    [InlineData("")]
    public void CronsWithInvalidFieldCountsAreRejected(string cron)
    {
        ScheduleSpec spec = ScheduleSpec.FromCron(cron);

        Assert.NotEmpty(spec.Validate());
    }

    [Fact]
    public void PositiveIntervalIsValid()
    {
        ScheduleSpec spec = ScheduleSpec.FromInterval(TimeSpan.FromMinutes(5));

        Assert.Empty(spec.Validate());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-60)]
    public void NonPositiveIntervalsAreRejected(int seconds)
    {
        ScheduleSpec spec = ScheduleSpec.FromInterval(TimeSpan.FromSeconds(seconds));

        Assert.NotEmpty(spec.Validate());
    }

    [Fact]
    public void OneShotIsValid()
    {
        ScheduleSpec spec = ScheduleSpec.FromOneShot(new DateTimeOffset(2027, 1, 1, 0, 0, 0, TimeSpan.Zero));

        Assert.Empty(spec.Validate());
    }

    [Fact]
    public void EmptySpecIsRejected()
    {
        ScheduleSpec spec = new();

        Assert.Contains(ScheduleSpecMissing, spec.Validate(), StringComparer.Ordinal);
    }

    [Fact]
    public void MultipleTriggersAreRejected()
    {
        ScheduleSpec spec = new()
        {
            Cron = "0 0 1 * *",
            Interval = TimeSpan.FromMinutes(5),
        };

        Assert.Contains(ScheduleSpecMultiple, spec.Validate(), StringComparer.Ordinal);
    }

    private const string ScheduleSpecMissing = "Exactly one of cron, interval, or oneShotAt must be set.";

    private const string ScheduleSpecMultiple = "Only one of cron, interval, or oneShotAt may be set.";
}

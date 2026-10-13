using Quartz;
using Scheduler.Contracts.Execution;
using Scheduler.Infrastructure.Scheduling;

namespace Scheduler.Tests.Unit.Scheduling;

public sealed class QuartzMisfireMapperTests
{
    [Theory]
    [InlineData(MisfirePolicy.FireOnce, CronTriggerMisfireInstruction.FireAndProceed)]
    [InlineData(MisfirePolicy.Skip, CronTriggerMisfireInstruction.DoNothing)]
    [InlineData(MisfirePolicy.RunImmediately, CronTriggerMisfireInstruction.FireAndProceed)]
    public void CronPolicyMapsToInstruction(MisfirePolicy policy, CronTriggerMisfireInstruction expected)
    {
        Assert.Equal(expected, QuartzMisfireMapper.MapCron(policy));
    }

    [Theory]
    [InlineData(MisfirePolicy.FireOnce, SimpleTriggerMisfireInstruction.FireNow)]
    [InlineData(MisfirePolicy.Skip, SimpleTriggerMisfireInstruction.NextWithRemainingCount)]
    [InlineData(MisfirePolicy.RunImmediately, SimpleTriggerMisfireInstruction.NowWithRemainingCount)]
    public void SimplePolicyMapsToInstruction(MisfirePolicy policy, SimpleTriggerMisfireInstruction expected)
    {
        Assert.Equal(expected, QuartzMisfireMapper.MapSimple(policy));
    }
}

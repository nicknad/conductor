using Quartz;
using Scheduler.Contracts.Execution;

namespace Scheduler.Infrastructure.Scheduling;

/// <summary>
/// Maps the platform's <see cref="MisfirePolicy" /> onto Quartz's per-family
/// misfire instructions. Cron triggers only distinguish "fire once now" from
/// "skip", so <see cref="MisfirePolicy.RunImmediately" /> collapses to
/// fire-and-proceed there; simple triggers can express all three intents.
/// </summary>
public static class QuartzMisfireMapper
{
    public static CronTriggerMisfireInstruction MapCron(MisfirePolicy policy) => policy switch
    {
        MisfirePolicy.FireOnce => CronTriggerMisfireInstruction.FireAndProceed,
        MisfirePolicy.Skip => CronTriggerMisfireInstruction.DoNothing,
        MisfirePolicy.RunImmediately => CronTriggerMisfireInstruction.FireAndProceed,
        _ => CronTriggerMisfireInstruction.SmartPolicy,
    };

    public static SimpleTriggerMisfireInstruction MapSimple(MisfirePolicy policy) => policy switch
    {
        MisfirePolicy.FireOnce => SimpleTriggerMisfireInstruction.FireNow,
        MisfirePolicy.Skip => SimpleTriggerMisfireInstruction.NextWithRemainingCount,
        MisfirePolicy.RunImmediately => SimpleTriggerMisfireInstruction.NowWithRemainingCount,
        _ => SimpleTriggerMisfireInstruction.SmartPolicy,
    };
}

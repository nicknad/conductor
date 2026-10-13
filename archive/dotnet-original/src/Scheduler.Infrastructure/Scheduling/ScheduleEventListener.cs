using Quartz;
using Scheduler.Application.Observability;

namespace Scheduler.Infrastructure.Scheduling;

/// <summary>
/// Records scheduled work as it happens: a durable <c>fired</c> event on each
/// trigger fire and a <c>missed</c>/<c>skipped</c> event when Quartz reports a
/// misfire or skip. This is the "scheduled work done / not run" signal; it never
/// reads or writes registry state.
/// </summary>
public sealed class ScheduleEventListener : ITriggerListener
{
    private readonly IScheduleEventRecorder _recorder;

    public ScheduleEventListener(IScheduleEventRecorder recorder)
    {
        ArgumentNullException.ThrowIfNull(recorder);
        _recorder = recorder;
    }

    public string Name => "scheduler-schedule-events";

    public async ValueTask TriggerFired(ITrigger trigger, IJobExecutionContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(trigger);
        await _recorder.RecordFiredAsync(trigger.JobKey.Name, cancellationToken);
    }

    public ValueTask<bool> VetoJobExecution(ITrigger trigger, IJobExecutionContext context, CancellationToken cancellationToken) =>
        ValueTask.FromResult(false);

    public async ValueTask TriggerMisfired(ITrigger trigger, IScheduler scheduler, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(trigger);
        await _recorder.RecordMisfiredAsync(trigger.JobKey.Name, cancellationToken);
    }

    public async ValueTask TriggerSkipped(ITrigger trigger, IScheduler scheduler, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(trigger);
        await _recorder.RecordSkippedAsync(trigger.JobKey.Name, cancellationToken);
    }

    public ValueTask TriggerComplete(
        ITrigger trigger,
        IJobExecutionContext context,
        SchedulerInstruction triggerInstructionCode,
        CancellationToken cancellationToken) => ValueTask.CompletedTask;

    public ValueTask TriggerRetriesExhausted(
        ITrigger trigger,
        IJobExecutionContext context,
        JobExecutionException exception,
        CancellationToken cancellationToken) => ValueTask.CompletedTask;
}

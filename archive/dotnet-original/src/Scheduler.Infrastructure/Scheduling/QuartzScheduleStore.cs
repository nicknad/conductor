using System.Globalization;
using Quartz;
using Scheduler.Application.Reconciliation;

namespace Scheduler.Infrastructure.Scheduling;

/// <summary>
/// The Quartz-backed <see cref="IScheduleStore" />. Every job and trigger key is
/// the stable platform job id inside <see cref="ScheduleOptions.JobGroup" />, and
/// all persisted data is string-only, so no .NET type is serialized into the
/// store. Apply is idempotent: it replaces a job and trigger in place.
/// </summary>
public sealed class QuartzScheduleStore : IScheduleStore
{
    private readonly ISchedulerFactory _schedulerFactory;
    private readonly ScheduleOptions _options;

    public QuartzScheduleStore(ISchedulerFactory schedulerFactory, ScheduleOptions options)
    {
        ArgumentNullException.ThrowIfNull(schedulerFactory);
        ArgumentNullException.ThrowIfNull(options);

        _schedulerFactory = schedulerFactory;
        _options = options;
    }

    public async Task<IReadOnlyList<ScheduledJob>> ListAsync(CancellationToken cancellationToken = default)
    {
        IScheduler scheduler = await _schedulerFactory.GetScheduler(cancellationToken);
        PagedResult<TriggerHeader> page = await scheduler.QueryTriggers(
            new TriggerQuery { Group = GroupMatcher<TriggerKey>.GroupEquals(_options.JobGroup) },
            cancellationToken);

        List<ScheduledJob> scheduled = [];
        foreach (TriggerHeader header in page.Items)
        {
            if (header.State is TriggerState.Paused or TriggerState.None)
            {
                continue;
            }

            ITrigger? trigger = await scheduler.GetTrigger(header.Key, cancellationToken);
            if (trigger is null)
            {
                continue;
            }

            JobDataMap data = trigger.JobDataMap;
            scheduled.Add(new ScheduledJob(
                header.Key.Name,
                data.GetString(ScheduleJobData.PluginId) ?? string.Empty,
                data.GetString(ScheduleJobData.Version) ?? string.Empty,
                ReadRevision(data)));
        }

        return scheduled;
    }

    public async Task ApplyAsync(ScheduleProjection projection, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(projection);

        IScheduler scheduler = await _schedulerFactory.GetScheduler(cancellationToken);
        JobKey jobKey = new(projection.JobId, _options.JobGroup);
        TriggerKey triggerKey = new(projection.JobId, _options.JobGroup);

        IJobDetail jobDetail = JobBuilder.Create<QuartzBridgeJob>()
            .WithIdentity(jobKey)
            .StoreDurably()
            .UsingJobData(ScheduleJobData.JobId, projection.JobId)
            .Build();

        ITrigger trigger = BuildTrigger(scheduler, triggerKey, jobKey, projection);

        await scheduler.AddJob(jobDetail, AddJobOptions.Replacing, cancellationToken);
        await scheduler.ScheduleTrigger(trigger, TriggerConflict.Replace, cancellationToken);
    }

    public async Task RemoveAsync(string jobId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(jobId);

        IScheduler scheduler = await _schedulerFactory.GetScheduler(cancellationToken);
        await scheduler.DeleteJob(new JobKey(jobId, _options.JobGroup), cancellationToken);
    }

    private static int ReadRevision(JobDataMap data)
    {
        string? revision = data.GetString(ScheduleJobData.Revision);
        return int.TryParse(revision, NumberStyles.Integer, CultureInfo.InvariantCulture, out int value) ? value : 0;
    }

    private static ITrigger BuildTrigger(
        IScheduler scheduler,
        TriggerKey triggerKey,
        JobKey jobKey,
        ScheduleProjection projection)
    {
        var builder = TriggerBuilder.Create(scheduler.TimeProvider)
            .WithIdentity(triggerKey)
            .ForJob(jobKey)
            .UsingJobData(ScheduleJobData.JobId, projection.JobId)
            .UsingJobData(ScheduleJobData.PluginId, projection.PluginId)
            .UsingJobData(ScheduleJobData.Version, projection.PluginVersion)
            .UsingJobData(
                ScheduleJobData.Revision,
                projection.ConfigurationRevision.ToString(CultureInfo.InvariantCulture));

        if (projection.Schedule.Cron is not null)
        {
            return builder
                .StartNow()
                .WithSchedule(
                    CronScheduleBuilder.Create(projection.Schedule.Cron)
                        .WithMisfireInstruction(QuartzMisfireMapper.MapCron(projection.MisfirePolicy)))
                .Build();
        }

        if (projection.Schedule.Interval is not null)
        {
            return builder
                .StartNow()
                .WithSchedule(
                    SimpleScheduleBuilder.Create()
                        .WithInterval(projection.Schedule.Interval.Value)
                        .RepeatForever()
                        .WithMisfireInstruction(QuartzMisfireMapper.MapSimple(projection.MisfirePolicy)))
                .Build();
        }

        if (projection.Schedule.OneShotAt is not null)
        {
            return builder
                .StartAt(projection.Schedule.OneShotAt.Value)
                .WithSchedule(
                    SimpleScheduleBuilder.Create()
                        .WithMisfireInstruction(QuartzMisfireMapper.MapSimple(projection.MisfirePolicy)))
                .Build();
        }

        throw new InvalidOperationException($"Job '{projection.JobId}' has no usable schedule specification.");
    }
}

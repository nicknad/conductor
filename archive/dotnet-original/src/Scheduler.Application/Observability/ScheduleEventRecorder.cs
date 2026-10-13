using Scheduler.Application.Persistence;
using Scheduler.Contracts.Execution;

namespace Scheduler.Application.Observability;

/// <summary>
/// Records schedule events for the configured group. A miss resolves the job's
/// current misfire policy when the job still exists, so the summary can attribute
/// "work not run" to it.
/// </summary>
public sealed class ScheduleEventRecorder : IScheduleEventRecorder
{
    private readonly IRegistryUnitOfWorkFactory _unitOfWorkFactory;
    private readonly TimeProvider _timeProvider;

    public ScheduleEventRecorder(IRegistryUnitOfWorkFactory unitOfWorkFactory, TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(unitOfWorkFactory);
        ArgumentNullException.ThrowIfNull(timeProvider);

        _unitOfWorkFactory = unitOfWorkFactory;
        _timeProvider = timeProvider;
    }

    public Task RecordFiredAsync(string jobId, CancellationToken cancellationToken = default) =>
        RecordAsync(jobId, ScheduleEventKind.Fired, resolveMisfirePolicy: false, cancellationToken);

    public Task RecordMisfiredAsync(string jobId, CancellationToken cancellationToken = default) =>
        RecordAsync(jobId, ScheduleEventKind.Missed, resolveMisfirePolicy: true, cancellationToken);

    public Task RecordSkippedAsync(string jobId, CancellationToken cancellationToken = default) =>
        RecordAsync(jobId, ScheduleEventKind.Skipped, resolveMisfirePolicy: true, cancellationToken);

    private async Task RecordAsync(
        string jobId,
        ScheduleEventKind kind,
        bool resolveMisfirePolicy,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(jobId);

        MisfirePolicy? misfirePolicy = null;
        if (resolveMisfirePolicy)
        {
            await using IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken);
            JobRecord? job = await unitOfWork.Jobs.GetAsync(jobId, cancellationToken);
            misfirePolicy = job?.Definition.MisfirePolicy;
        }

        await using IRegistryUnitOfWork write = await _unitOfWorkFactory.BeginAsync(cancellationToken);
        await write.ScheduleEvents.RecordAsync(
            new ScheduleEvent
            {
                Timestamp = _timeProvider.GetUtcNow(),
                JobId = jobId,
                Kind = kind,
                MisfirePolicy = misfirePolicy,
            },
            cancellationToken);
        await write.CommitAsync(cancellationToken);
    }
}

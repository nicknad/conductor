using Scheduler.Application.Execution;
using Scheduler.Application.Persistence;
using Scheduler.Application.Reconciliation;
using Scheduler.Contracts.Jobs;

namespace Scheduler.Application.JobManagement;

/// <summary>
/// Job configuration use cases over the authoritative registry. Updating a
/// definition bumps its configuration revision; new executions use the new
/// revision, running ones keep theirs. Manual runs dispatch through the same
/// path as scheduled runs.
/// </summary>
public sealed class JobManager : IJobManager
{
    private const string Actor = "local";

    private readonly IRegistryUnitOfWorkFactory _unitOfWorkFactory;
    private readonly IDispatcher _dispatcher;
    private readonly IAuditWriter _auditWriter;
    private readonly TimeProvider _timeProvider;

    public JobManager(
        IRegistryUnitOfWorkFactory unitOfWorkFactory,
        IDispatcher dispatcher,
        IAuditWriter auditWriter,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(unitOfWorkFactory);
        ArgumentNullException.ThrowIfNull(dispatcher);
        ArgumentNullException.ThrowIfNull(auditWriter);
        ArgumentNullException.ThrowIfNull(timeProvider);

        _unitOfWorkFactory = unitOfWorkFactory;
        _dispatcher = dispatcher;
        _auditWriter = auditWriter;
        _timeProvider = timeProvider;
    }

    public async Task<IReadOnlyList<JobDefinition>> ListAsync(CancellationToken cancellationToken = default)
    {
        await using IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken);
        IReadOnlyList<JobRecord> jobs = await unitOfWork.Jobs.ListAsync(cancellationToken);
        return jobs.Select(job => job.Definition).ToList();
    }

    public async Task<JobDefinition?> GetAsync(string jobId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(jobId);

        await using IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken);
        JobRecord? job = await unitOfWork.Jobs.GetAsync(jobId, cancellationToken);
        return job?.Definition;
    }

    public async Task<JobDefinition> UpdateAsync(JobDefinition definition, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(definition);

        IReadOnlyList<string> errors = definition.Validate();
        if (errors.Count > 0)
        {
            throw new JobValidationException(errors);
        }

        await using IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken);
        JobRecord? existing = await unitOfWork.Jobs.GetAsync(definition.JobId, cancellationToken);
        int revision = (existing?.ConfigurationRevision ?? 0) + 1;

        DateTimeOffset now = _timeProvider.GetUtcNow();
        JobRecord updated = new()
        {
            Definition = definition,
            ConfigurationRevision = revision,
            UpdatedAt = now,
        };

        await unitOfWork.Jobs.UpsertAsync(updated, cancellationToken);
        await unitOfWork.Operations.CreateAsync(
            ScheduleChangeOutbox.Create(
                Guid.NewGuid(),
                updated,
                existing is null ? ScheduleChangeAction.Create : ScheduleChangeAction.Update,
                now),
            cancellationToken);
        await unitOfWork.CommitAsync(cancellationToken);

        return definition;
    }

    public async Task SetEnabledAsync(string jobId, bool enabled, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(jobId);

        await using IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken);
        JobRecord job = await unitOfWork.Jobs.GetAsync(jobId, cancellationToken)
            ?? throw new KeyNotFoundException($"Job '{jobId}' was not found.");

        DateTimeOffset now = _timeProvider.GetUtcNow();
        await unitOfWork.Jobs.SetEnabledAsync(jobId, enabled, now, cancellationToken);
        await unitOfWork.Operations.CreateAsync(
            ScheduleChangeOutbox.Create(
                Guid.NewGuid(),
                job with { Definition = job.Definition with { Enabled = enabled }, UpdatedAt = now },
                enabled ? ScheduleChangeAction.Update : ScheduleChangeAction.Pause,
                now),
            cancellationToken);
        await unitOfWork.CommitAsync(cancellationToken);
    }

    public async Task<Guid> RunNowAsync(string jobId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(jobId);

        try
        {
            Guid executionId = await _dispatcher.DispatchAsync(jobId, cancellationToken);
            await _auditWriter.RecordAsync(
                Actor,
                "job.run",
                jobId,
                $"executionId={executionId:D}",
                cancellationToken);
            return executionId;
        }
        catch (DispatchRejectedException exception)
        {
            await _auditWriter.RecordAsync(
                Actor,
                "job.run.rejected",
                jobId,
                $"reason={exception.Reason}",
                CancellationToken.None);
            throw;
        }
    }
}

/// <summary>Thrown when a job definition fails validation before it is persisted.</summary>
public sealed class JobValidationException(IReadOnlyList<string> errors)
    : Exception("The job definition is not valid: " + string.Join("; ", errors))
{
    public IReadOnlyList<string> Errors { get; } = errors;
}

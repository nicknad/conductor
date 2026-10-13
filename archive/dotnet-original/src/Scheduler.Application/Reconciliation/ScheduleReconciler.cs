using Scheduler.Application.Observability;
using Scheduler.Application.Persistence;
using Scheduler.Application.PluginManagement;
using Scheduler.Contracts.Jobs;

namespace Scheduler.Application.Reconciliation;

/// <summary>
/// Converges the Quartz store toward the authoritative registry:
/// <list type="number">
/// <item>resumes or rolls back incomplete lifecycle operations,</item>
/// <item>applies non-terminal outbox schedule changes (apply-then-mark, idempotent),</item>
/// <item>repairs drift toward the registry (rogue triggers removed, enabled jobs without
///       triggers scheduled, stale revisions refreshed).</item>
/// </list>
/// It is the only component that reaches the scheduler store; the plugin and job managers
/// publish durable outbox records and never touch Quartz themselves. Sweeps are serialized so
/// the periodic loop and the post-lifecycle trigger cannot race each other. Each sweep's
/// outcome is recorded durably and exposed via <see cref="IReconciliationStatus" />.
/// </summary>
public sealed class ScheduleReconciler : IReconciler, IReconciliationStatus, IDisposable
{
    private const string Actor = "reconciler";

    private readonly IRegistryUnitOfWorkFactory _unitOfWorkFactory;
    private readonly IScheduleStore _scheduleStore;
    private readonly IAuditWriter _auditWriter;
    private readonly TimeProvider _timeProvider;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly object _statusLock = new();
    private DateTimeOffset? _lastSucceededAt;
    private DateTimeOffset? _lastFailedAt;
    private int _lastErrorCount;

    public ScheduleReconciler(
        IRegistryUnitOfWorkFactory unitOfWorkFactory,
        IScheduleStore scheduleStore,
        IAuditWriter auditWriter,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(unitOfWorkFactory);
        ArgumentNullException.ThrowIfNull(scheduleStore);
        ArgumentNullException.ThrowIfNull(auditWriter);
        ArgumentNullException.ThrowIfNull(timeProvider);

        _unitOfWorkFactory = unitOfWorkFactory;
        _scheduleStore = scheduleStore;
        _auditWriter = auditWriter;
        _timeProvider = timeProvider;
    }

    public async Task<ReconciliationResult> ReconcileAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            return await ReconcileCoreAsync(cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public void Dispose()
    {
        _gate.Dispose();
        GC.SuppressFinalize(this);
    }

    private async Task<ReconciliationResult> ReconcileCoreAsync(CancellationToken cancellationToken)
    {
        List<string> errors = [];

        int completed = 0;
        int rolledBack = 0;
        foreach (OperationState terminal in await ReconcileLifecycleOperationsAsync(errors, cancellationToken))
        {
            if (terminal == OperationState.Succeeded)
            {
                completed++;
            }
            else
            {
                rolledBack++;
            }
        }

        int synchronized = await ApplyOutboxAsync(errors, cancellationToken);
        synchronized += await RepairDriftAsync(errors, cancellationToken);

        await RecordOutcomeAsync(completed, rolledBack, synchronized, errors, cancellationToken);
        await RecordRunAsync(completed, rolledBack, synchronized, errors.Count, cancellationToken);
        return new ReconciliationResult(completed, rolledBack, synchronized, errors);
    }

    public DateTimeOffset? LastSucceededAt
    {
        get
        {
            lock (_statusLock)
            {
                return _lastSucceededAt;
            }
        }
    }

    public DateTimeOffset? LastFailedAt
    {
        get
        {
            lock (_statusLock)
            {
                return _lastFailedAt;
            }
        }
    }

    public int LastErrorCount
    {
        get
        {
            lock (_statusLock)
            {
                return _lastErrorCount;
            }
        }
    }

    private async Task<IReadOnlyList<OperationState>> ReconcileLifecycleOperationsAsync(
        List<string> errors,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<OperationRecord> outstanding;
        await using (IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken))
        {
            outstanding = await unitOfWork.Operations.ListNonTerminalAsync(cancellationToken);
        }

        List<OperationState> results = [];
        foreach (OperationRecord operation in outstanding)
        {
            if (operation.Kind == OperationKind.ScheduleChange)
            {
                continue;
            }

            OperationState terminal;
            string detail;
            try
            {
                (terminal, detail) = await DecideLifecycleAsync(operation, cancellationToken);
                // A crash can leave an operation Pending before its first Running write; the
                // state machine only reaches a terminal state from Running.
                if (operation.State == OperationState.Pending)
                {
                    await TransitionAsync(operation.OperationId, OperationState.Running, cancellationToken);
                }

                await TransitionAsync(operation.OperationId, terminal, cancellationToken);
            }
            catch (Exception exception)
            {
                errors.Add($"lifecycle {operation.OperationId} ({operation.Kind}): {exception.Message}");
                continue;
            }

            await _auditWriter.RecordAsync(
                Actor,
                "reconcile.lifecycle." + terminal,
                operation.Kind.ToString(),
                detail,
                cancellationToken);
            results.Add(terminal);
        }

        return results;
    }

    private async Task<(OperationState Terminal, string Detail)> DecideLifecycleAsync(
        OperationRecord operation,
        CancellationToken cancellationToken)
    {
        (string pluginId, Version? version) = ReadLifecycleIdentity(operation);
        await using IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken);

        switch (operation.Kind)
        {
            case OperationKind.Install:
                {
                    PluginVersionRecord? record = version is null
                        ? null
                        : await unitOfWork.Plugins.GetVersionAsync(pluginId, version, cancellationToken);
                    return record is not null && record.State.IsPublished()
                        ? (OperationState.Succeeded, "install already published")
                        : (OperationState.Failed, "install did not promote");
                }

            case OperationKind.Activate:
            case OperationKind.Rollback:
                {
                    PluginActivationRecord? activation = await unitOfWork.Plugins.GetActivationAsync(pluginId, cancellationToken);
                    return activation?.Version == version
                        ? (OperationState.Succeeded, "activation already published")
                        : (OperationState.RolledBack, "activation did not publish; previous version retained");
                }

            case OperationKind.Deactivate:
                {
                    PluginActivationRecord? activation = await unitOfWork.Plugins.GetActivationAsync(pluginId, cancellationToken);
                    return activation is null || activation.Version != version
                        ? (OperationState.Succeeded, "deactivation already applied")
                        : (OperationState.RolledBack, "deactivation did not complete; version still active");
                }

            case OperationKind.Remove:
                {
                    PluginVersionRecord? record = version is null
                        ? null
                        : await unitOfWork.Plugins.GetVersionAsync(pluginId, version, cancellationToken);
                    return record is null || record.State == PluginLifecycleState.Removed
                        ? (OperationState.Succeeded, "removal already applied")
                        : (OperationState.RolledBack, "removal did not complete; version retained");
                }

            default:
                return (OperationState.RolledBack, $"unsupported lifecycle operation '{operation.Kind}'");
        }
    }

    private async Task<int> ApplyOutboxAsync(List<string> errors, CancellationToken cancellationToken)
    {
        IReadOnlyList<OperationRecord> nonTerminal;
        await using (IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken))
        {
            nonTerminal = await unitOfWork.Operations.ListNonTerminalAsync(cancellationToken);
        }

        int applied = 0;
        foreach (OperationRecord operation in nonTerminal)
        {
            if (operation.Kind != OperationKind.ScheduleChange)
            {
                continue;
            }

            try
            {
                ScheduleChangePayload payload =
                    OperationPayloadCodec.Deserialize<ScheduleChangePayload>(operation.Payload);
                EnsureSupportedVersion(payload.PayloadVersion, ScheduleChangePayload.CurrentVersion);

                // A record may be Pending (never applied) or Running (crash mid-apply); both are
                // converged idempotently and then marked terminal.
                if (operation.State == OperationState.Pending)
                {
                    await TransitionAsync(operation.OperationId, OperationState.Running, cancellationToken);
                }

                await ConvergeJobAsync(payload.JobId, cancellationToken);
                await TransitionAsync(operation.OperationId, OperationState.Succeeded, cancellationToken);
                applied++;
            }
            catch (Exception exception)
            {
                errors.Add($"schedule change {operation.OperationId}: {exception.Message}");
                await MarkFailedAsync(operation.OperationId, cancellationToken);
            }
        }

        return applied;
    }

    private async Task<int> RepairDriftAsync(List<string> errors, CancellationToken cancellationToken)
    {
        Dictionary<string, ScheduleProjection> desired;
        await using (IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken))
        {
            desired = await BuildDesiredProjectionsAsync(unitOfWork, cancellationToken);
        }

        IReadOnlyList<ScheduledJob> scheduled = await _scheduleStore.ListAsync(cancellationToken);
        HashSet<string> scheduledIds = new(scheduled.Select(job => job.JobId), StringComparer.Ordinal);

        int repaired = 0;
        foreach (ScheduledJob job in scheduled)
        {
            try
            {
                if (!desired.TryGetValue(job.JobId, out ScheduleProjection? target))
                {
                    await _scheduleStore.RemoveAsync(job.JobId, cancellationToken);
                    repaired++;
                }
                else if (!Matches(job, target))
                {
                    await _scheduleStore.ApplyAsync(target, cancellationToken);
                    repaired++;
                }
            }
            catch (Exception exception)
            {
                errors.Add($"drift '{job.JobId}': {exception.Message}");
            }
        }

        foreach ((string jobId, ScheduleProjection target) in desired)
        {
            if (scheduledIds.Contains(jobId))
            {
                continue;
            }

            try
            {
                await _scheduleStore.ApplyAsync(target, cancellationToken);
                repaired++;
            }
            catch (Exception exception)
            {
                errors.Add($"drift '{jobId}': {exception.Message}");
            }
        }

        return repaired;
    }

    private async Task<Dictionary<string, ScheduleProjection>> BuildDesiredProjectionsAsync(
        IRegistryUnitOfWork unitOfWork,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<JobRecord> jobs = await unitOfWork.Jobs.ListAsync(cancellationToken);
        Dictionary<string, ScheduleProjection> desired = new(StringComparer.Ordinal);

        foreach (JobRecord job in jobs)
        {
            if (!IsSchedulable(job.Definition))
            {
                continue;
            }

            PluginActivationRecord? activation =
                await unitOfWork.Plugins.GetActivationAsync(job.Definition.PluginId, cancellationToken);
            if (activation is null)
            {
                continue;
            }

            desired[job.Definition.JobId] = ToProjection(job);
        }

        return desired;
    }

    private async Task ConvergeJobAsync(string jobId, CancellationToken cancellationToken)
    {
        JobRecord? job;
        bool pluginActive;
        await using (IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken))
        {
            job = await unitOfWork.Jobs.GetAsync(jobId, cancellationToken);
            pluginActive = job is not null
                && await unitOfWork.Plugins.GetActivationAsync(job.Definition.PluginId, cancellationToken) is not null;
        }

        if (job is null || !pluginActive || !IsSchedulable(job.Definition))
        {
            await _scheduleStore.RemoveAsync(jobId, cancellationToken);
            return;
        }

        await _scheduleStore.ApplyAsync(ToProjection(job), cancellationToken);
    }

    /// <summary>
    /// A job is schedulable when it is enabled, its plugin is active, and — for a one-shot —
    /// its fire time is still in the future. A past one-shot is treated as consumed so a
    /// completed trigger is never recreated (and re-fired) on the next sweep.
    /// </summary>
    private bool IsSchedulable(JobDefinition definition)
    {
        if (!definition.Enabled)
        {
            return false;
        }

        return definition.Schedule.OneShotAt is not { } oneShot || oneShot > _timeProvider.GetUtcNow();
    }

    private async Task TransitionAsync(Guid operationId, OperationState state, CancellationToken cancellationToken)
    {
        await using IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken);
        await unitOfWork.Operations.UpdateStateAsync(
            operationId,
            state,
            payload: null,
            _timeProvider.GetUtcNow(),
            cancellationToken);
        await unitOfWork.CommitAsync(cancellationToken);
    }

    private async Task MarkFailedAsync(Guid operationId, CancellationToken cancellationToken)
    {
        await using IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken);
        OperationRecord? operation = await unitOfWork.Operations.GetAsync(operationId, cancellationToken);
        if (operation is null || OperationTransitions.IsTerminal(operation.State))
        {
            return;
        }

        await unitOfWork.Operations.UpdateStateAsync(
            operationId,
            OperationState.Failed,
            payload: null,
            _timeProvider.GetUtcNow(),
            cancellationToken);
        await unitOfWork.CommitAsync(cancellationToken);
    }

    private Task RecordOutcomeAsync(
        int completed,
        int rolledBack,
        int synchronized,
        List<string> errors,
        CancellationToken cancellationToken)
    {
        bool failed = errors.Count > 0;
        return _auditWriter.RecordAsync(
            Actor,
            failed ? "reconcile.failed" : "reconcile.completed",
            "scheduler",
            $"completed={completed};rolledBack={rolledBack};synchronized={synchronized};errors={errors.Count}",
            cancellationToken);
    }

    private async Task RecordRunAsync(
        int completed,
        int rolledBack,
        int synchronized,
        int errorCount,
        CancellationToken cancellationToken)
    {
        bool succeeded = errorCount == 0;
        DateTimeOffset now = _timeProvider.GetUtcNow();

        await using IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken);
        await unitOfWork.ReconciliationRuns.RecordAsync(
            new ReconciliationRun
            {
                Timestamp = now,
                Completed = completed,
                RolledBack = rolledBack,
                Synchronized = synchronized,
                ErrorCount = errorCount,
                Succeeded = succeeded,
            },
            cancellationToken);
        await unitOfWork.CommitAsync(cancellationToken);

        lock (_statusLock)
        {
            _lastErrorCount = errorCount;
            if (succeeded)
            {
                _lastSucceededAt = now;
            }
            else
            {
                _lastFailedAt = now;
            }
        }
    }

    private static (string PluginId, Version? Version) ReadLifecycleIdentity(OperationRecord operation)
    {
        if (operation.Kind == OperationKind.Install)
        {
            InstallOperationPayload payload =
                OperationPayloadCodec.Deserialize<InstallOperationPayload>(operation.Payload);
            EnsureSupportedVersion(payload.PayloadVersion, InstallOperationPayload.CurrentVersion);
            return (payload.PluginId ?? string.Empty, ParseVersion(payload.Version));
        }

        LifecycleOperationPayload lifecycle =
            OperationPayloadCodec.Deserialize<LifecycleOperationPayload>(operation.Payload);
        EnsureSupportedVersion(lifecycle.PayloadVersion, LifecycleOperationPayload.CurrentVersion);
        return (lifecycle.PluginId, ParseVersion(lifecycle.Version));
    }

    private static Version? ParseVersion(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : Version.Parse(value);

    private static void EnsureSupportedVersion(int payloadVersion, int supportedVersion)
    {
        if (payloadVersion > supportedVersion)
        {
            throw new InvalidOperationException(
                $"Operation payload version {payloadVersion} is newer than this host supports.");
        }
    }

    private static ScheduleProjection ToProjection(JobRecord job) => new(
        job.Definition.JobId,
        job.Definition.PluginId,
        job.Definition.PluginVersion.ToString(),
        job.ConfigurationRevision,
        job.Definition.Schedule,
        job.Definition.MisfirePolicy);

    private static bool Matches(ScheduledJob scheduled, ScheduleProjection target) =>
        scheduled.ConfigurationRevision == target.ConfigurationRevision
        && string.Equals(scheduled.PluginVersion, target.PluginVersion, StringComparison.Ordinal)
        && string.Equals(scheduled.PluginId, target.PluginId, StringComparison.Ordinal);
}

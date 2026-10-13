using Scheduler.Application.Observability;
using Scheduler.Application.Persistence;
using Scheduler.Application.PluginManagement;
using Scheduler.Contracts.Plugins;

namespace Scheduler.Application.Execution;

/// <summary>
/// Resolves the active plugin version for a job, admits the execution under the
/// concurrency policy, and runs it through the configured backend. Existing
/// executions keep their pinned version and revision; only new dispatches follow
/// a version change. A dispatch that is not admitted is recorded durably with a
/// structured reason before the failure is raised.
/// </summary>
public sealed class Dispatcher : IDispatcher
{
    private readonly IRegistryUnitOfWorkFactory _unitOfWorkFactory;
    private readonly IPluginRuntime _pluginRuntime;
    private readonly IExecutionBackend _backend;
    private readonly ExecutionRunner _runner;
    private readonly ConcurrencyGate _gate;
    private readonly IRunningExecutionRegistry _running;
    private readonly IExecutionRejectionWriter _rejections;
    private readonly ShutdownSignal _shutdown;
    private readonly TimeProvider _timeProvider;

    public Dispatcher(
        IRegistryUnitOfWorkFactory unitOfWorkFactory,
        IPluginRuntime pluginRuntime,
        IExecutionBackend backend,
        ExecutionRunner runner,
        ConcurrencyGate gate,
        IRunningExecutionRegistry running,
        IExecutionRejectionWriter rejections,
        ShutdownSignal shutdown,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(unitOfWorkFactory);
        ArgumentNullException.ThrowIfNull(pluginRuntime);
        ArgumentNullException.ThrowIfNull(backend);
        ArgumentNullException.ThrowIfNull(runner);
        ArgumentNullException.ThrowIfNull(gate);
        ArgumentNullException.ThrowIfNull(running);
        ArgumentNullException.ThrowIfNull(rejections);
        ArgumentNullException.ThrowIfNull(shutdown);
        ArgumentNullException.ThrowIfNull(timeProvider);

        _unitOfWorkFactory = unitOfWorkFactory;
        _pluginRuntime = pluginRuntime;
        _backend = backend;
        _runner = runner;
        _gate = gate;
        _running = running;
        _rejections = rejections;
        _shutdown = shutdown;
        _timeProvider = timeProvider;
    }

    public async Task<Guid> DispatchAsync(string jobId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(jobId);

        if (_shutdown.IsShuttingDown)
        {
            await _rejections.RecordAsync(
                jobId,
                pluginId: null,
                ExecutionRejectionReason.ShuttingDown,
                $"Job '{jobId}' was not admitted because the host is shutting down.",
                CancellationToken.None);
            throw new DispatchRejectedException(
                ExecutionRejectionReason.ShuttingDown,
                "The host is shutting down and is not accepting new executions.");
        }

        JobRecord? job = await GetJobAsync(jobId, cancellationToken);
        if (job is null)
        {
            await _rejections.RecordAsync(
                jobId,
                pluginId: null,
                ExecutionRejectionReason.NotFound,
                $"Job '{jobId}' was not found.",
                cancellationToken);
            throw new KeyNotFoundException($"Job '{jobId}' was not found.");
        }

        if (!job.Definition.Enabled)
        {
            await _rejections.RecordAsync(
                jobId,
                job.Definition.PluginId,
                ExecutionRejectionReason.Disabled,
                $"Job '{jobId}' is disabled.",
                cancellationToken);
            throw new DispatchRejectedException(
                ExecutionRejectionReason.Disabled,
                $"Job '{jobId}' is disabled.");
        }

        if (job.Definition.ExecutionMode != _backend.Mode)
        {
            await _rejections.RecordAsync(
                jobId,
                job.Definition.PluginId,
                ExecutionRejectionReason.ModeUnavailable,
                $"Execution mode '{job.Definition.ExecutionMode}' is not available on this host.",
                cancellationToken);
            throw new DispatchRejectedException(
                ExecutionRejectionReason.ModeUnavailable,
                $"Execution mode '{job.Definition.ExecutionMode}' is not available on this host.");
        }

        Version? activeVersion = await ResolveActiveVersionAsync(job.Definition.PluginId, cancellationToken);
        if (activeVersion is null)
        {
            await _rejections.RecordAsync(
                jobId,
                job.Definition.PluginId,
                ExecutionRejectionReason.NoActiveVersion,
                $"Plugin '{job.Definition.PluginId}' has no active version.",
                cancellationToken);
            throw new DispatchRejectedException(
                ExecutionRejectionReason.NoActiveVersion,
                $"Plugin '{job.Definition.PluginId}' has no active version; activate it before running jobs.");
        }

        IJobHandler? handler = _pluginRuntime.ResolveHandler(jobId, job.Definition.PluginId, activeVersion);
        if (handler is null)
        {
            await _rejections.RecordAsync(
                jobId,
                job.Definition.PluginId,
                ExecutionRejectionReason.NoHandler,
                $"No handler for job '{jobId}' in active plugin '{job.Definition.PluginId}' '{activeVersion}'.",
                cancellationToken);
            throw new DispatchRejectedException(
                ExecutionRejectionReason.NoHandler,
                $"No handler for job '{jobId}' in active plugin '{job.Definition.PluginId}' '{activeVersion}'.");
        }

        Guid executionId = Guid.NewGuid();
        string correlationId = executionId.ToString("N");
        using IRunningExecution running = _running.Register(
            executionId,
            job.Definition.PluginId,
            activeVersion,
            CancellationToken.None);

        IDisposable slot;
        try
        {
            slot = await _gate.AcquireAsync(jobId, job.Definition.ConcurrencyPolicy, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            await _rejections.RecordAsync(
                jobId,
                job.Definition.PluginId,
                ExecutionRejectionReason.Concurrency,
                "Admission was abandoned while waiting for a concurrency slot.",
                CancellationToken.None);
            throw;
        }

        using (slot)
        {
            ExecutionRequest request = new(
                jobId,
                job.Definition.PluginId,
                activeVersion,
                job.ConfigurationRevision,
                executionId,
                correlationId,
                _timeProvider.GetUtcNow(),
                job.Definition.Parameters,
                job.Definition.Timeout,
                job.Definition.RetryPolicy,
                handler);

            await _runner.RunAsync(request, running);
        }

        return executionId;
    }

    public Task<bool> CancelAsync(Guid executionId, string reason, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        return Task.FromResult(_running.TryCancel(executionId, reason));
    }

    private async Task<JobRecord?> GetJobAsync(string jobId, CancellationToken cancellationToken)
    {
        await using IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken);
        return await unitOfWork.Jobs.GetAsync(jobId, cancellationToken);
    }

    private async Task<Version?> ResolveActiveVersionAsync(string pluginId, CancellationToken cancellationToken)
    {
        await using IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken);
        PluginActivationRecord? activation = await unitOfWork.Plugins.GetActivationAsync(pluginId, cancellationToken);
        return activation?.Version;
    }
}

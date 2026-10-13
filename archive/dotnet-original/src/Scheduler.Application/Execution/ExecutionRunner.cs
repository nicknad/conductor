using Scheduler.Application.Observability;
using Scheduler.Application.Persistence;
using Scheduler.Application.Secrets;
using Scheduler.Contracts.Execution;
using Scheduler.Contracts.Plugins;
using Scheduler.Contracts.Secrets;

namespace Scheduler.Application.Execution;

/// <summary>
/// A pinned, admitted execution: the plugin version and configuration revision
/// are fixed here and never change while the execution runs. Handler resolution
/// has already happened.
/// </summary>
public sealed record ExecutionRequest(
    string JobId,
    string PluginId,
    Version PluginVersion,
    int ConfigurationRevision,
    Guid ExecutionId,
    string CorrelationId,
    DateTimeOffset ScheduledAt,
    IReadOnlyDictionary<string, string?> Parameters,
    TimeSpan Timeout,
    RetryPolicy RetryPolicy,
    IJobHandler Handler);

/// <summary>
/// Runs one admitted execution to a terminal state: durable Pending → Running →
/// terminal, per-attempt timeout and cancellation propagation, sanitized errors,
/// and bounded retry using <see cref="RetryPolicyEvaluator" />. A thrown
/// exception is treated as a retryable failure; a handler-reported failure is
/// retried only when it is marked retryable.
/// </summary>
public sealed class ExecutionRunner
{
    private readonly IRegistryUnitOfWorkFactory _unitOfWorkFactory;
    private readonly IExecutionBackend _backend;
    private readonly ISecretProviderFactory _secretProviderFactory;
    private readonly RetryPolicyEvaluator _retryEvaluator;
    private readonly TimeProvider _timeProvider;

    public ExecutionRunner(
        IRegistryUnitOfWorkFactory unitOfWorkFactory,
        IExecutionBackend backend,
        ISecretProviderFactory secretProviderFactory,
        RetryPolicyEvaluator retryEvaluator,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(unitOfWorkFactory);
        ArgumentNullException.ThrowIfNull(backend);
        ArgumentNullException.ThrowIfNull(secretProviderFactory);
        ArgumentNullException.ThrowIfNull(retryEvaluator);
        ArgumentNullException.ThrowIfNull(timeProvider);

        _unitOfWorkFactory = unitOfWorkFactory;
        _backend = backend;
        _secretProviderFactory = secretProviderFactory;
        _retryEvaluator = retryEvaluator;
        _timeProvider = timeProvider;
    }

    public async Task<JobExecutionStatus> RunAsync(
        ExecutionRequest request,
        IRunningExecution running)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(running);

        ExecutionRecord record = new()
        {
            ExecutionId = request.ExecutionId,
            JobId = request.JobId,
            PluginId = request.PluginId,
            PluginVersion = request.PluginVersion,
            ConfigurationRevision = request.ConfigurationRevision,
            Attempt = 1,
            Status = JobExecutionStatus.Pending,
            CorrelationId = request.CorrelationId,
            ScheduledAt = request.ScheduledAt,
        };
        await CreateAsync(record);

        ExecutionIdentity identity = new(
            request.ExecutionId,
            request.CorrelationId,
            request.JobId,
            request.PluginId,
            request.PluginVersion);
        ISecretProvider secrets = await _secretProviderFactory.CreateAsync(identity, CancellationToken.None);

        DateTimeOffset? startedAt = null;
        int attempt = 1;
        JobExecutionStatus status;
        string? summary = null;
        string? cancellationReason = null;

        while (true)
        {
            DateTimeOffset now = _timeProvider.GetUtcNow();
            startedAt ??= now;
            record = record with { Status = JobExecutionStatus.Running, StartedAt = startedAt, Attempt = attempt };
            await UpdateAsync(record);

            using CancellationTokenSource timeout = new(request.Timeout);
            using CancellationTokenSource linked =
                CancellationTokenSource.CreateLinkedTokenSource(running.Token, timeout.Token);

            JobResult result;
            try
            {
                result = await _backend.ExecuteAsync(
                    new ExecutionInvocation(
                        request.Handler,
                        request.ExecutionId,
                        request.JobId,
                        request.PluginId,
                        request.PluginVersion,
                        request.ConfigurationRevision,
                        request.ScheduledAt,
                        now.Add(request.Timeout),
                        request.CorrelationId,
                        request.Parameters,
                        secrets),
                    linked.Token);
            }
            catch (OperationCanceledException) when (timeout.IsCancellationRequested)
            {
                status = JobExecutionStatus.TimedOut;
                summary = "Execution timed out.";
                break;
            }
            catch (OperationCanceledException)
            {
                status = JobExecutionStatus.Cancelled;
                cancellationReason = running.CancellationReason ?? "Execution was cancelled.";
                summary = cancellationReason;
                break;
            }
            catch (SecretNotAuthorizedException exception)
            {
                // An authorization denial is permanent for this execution; never retry it.
                result = JobResult.Failed(ErrorSanitizer.Sanitize(exception), retryable: false);
            }
            catch (Exception exception)
            {
                result = JobResult.Failed(ErrorSanitizer.Sanitize(exception), retryable: true);
            }

            if (result.Outcome == JobOutcome.Succeeded)
            {
                status = JobExecutionStatus.Succeeded;
                summary = result.Summary;
                break;
            }

            RetryDecision decision = _retryEvaluator.Evaluate(
                request.RetryPolicy,
                attempt,
                result.Retryable ? FailureKind.Retryable : FailureKind.NonRetryable);

            if (!decision.ShouldRetry)
            {
                status = JobExecutionStatus.Failed;
                summary = result.Summary;
                break;
            }

            try
            {
                await Task.Delay(decision.Delay, running.Token);
            }
            catch (OperationCanceledException)
            {
                status = JobExecutionStatus.Cancelled;
                cancellationReason = running.CancellationReason ?? "Execution was cancelled.";
                summary = cancellationReason;
                break;
            }

            attempt = decision.NextAttempt;
        }

        record = record with
        {
            Status = status,
            StartedAt = startedAt,
            EndedAt = _timeProvider.GetUtcNow(),
            Attempt = attempt,
            ResultSummary = summary,
            CancellationReason = cancellationReason,
        };
        await UpdateAsync(record);
        return status;
    }

    private async Task CreateAsync(ExecutionRecord record)
    {
        await using IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(CancellationToken.None);
        await unitOfWork.Executions.CreateAsync(record, CancellationToken.None);
        await unitOfWork.CommitAsync(CancellationToken.None);
    }

    private async Task UpdateAsync(ExecutionRecord record)
    {
        await using IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(CancellationToken.None);
        await unitOfWork.Executions.UpdateAsync(record, CancellationToken.None);
        await unitOfWork.CommitAsync(CancellationToken.None);
    }
}

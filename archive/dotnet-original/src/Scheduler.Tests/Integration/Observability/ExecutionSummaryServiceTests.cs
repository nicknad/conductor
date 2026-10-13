using Scheduler.Application.Observability;
using Scheduler.Application.Persistence;
using Scheduler.Contracts.Execution;
using Scheduler.Infrastructure.Observability;

namespace Scheduler.Tests.Integration.Observability;

public sealed class ExecutionSummaryServiceTests
{
    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task SummaryAggregatesDurableDoneAndNotDoneState()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);
        DateTimeOffset now = DateTimeOffset.UtcNow;

        await using (IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken))
        {
            await unitOfWork.Executions.CreateAsync(Execution("job-1", JobExecutionStatus.Succeeded, attempt: 1, now), CancellationToken);
            await unitOfWork.Executions.CreateAsync(Execution("job-1", JobExecutionStatus.Succeeded, attempt: 3, now), CancellationToken);
            await unitOfWork.Executions.CreateAsync(Execution("job-2", JobExecutionStatus.Failed, attempt: 1, now), CancellationToken);
            await unitOfWork.Executions.CreateAsync(Execution("job-3", JobExecutionStatus.Running, attempt: 1, now), CancellationToken);

            await unitOfWork.Rejections.RecordAsync(Rejection("job-4", ExecutionRejectionReason.Disabled, now), CancellationToken);
            await unitOfWork.Rejections.RecordAsync(Rejection("job-5", ExecutionRejectionReason.NoActiveVersion, now), CancellationToken);

            await unitOfWork.ScheduleEvents.RecordAsync(ScheduleEvent("job-1", ScheduleEventKind.Fired, now), CancellationToken);
            await unitOfWork.ScheduleEvents.RecordAsync(ScheduleEvent("job-1", ScheduleEventKind.Fired, now), CancellationToken);
            await unitOfWork.ScheduleEvents.RecordAsync(ScheduleEvent("job-1", ScheduleEventKind.Missed, now), CancellationToken);

            await unitOfWork.Operations.CreateAsync(Operation(OperationKind.ScheduleChange, OperationState.Succeeded, now), CancellationToken);
            await unitOfWork.Operations.CreateAsync(Operation(OperationKind.Activate, OperationState.Succeeded, now), CancellationToken);
            await unitOfWork.Operations.CreateAsync(Operation(OperationKind.Deactivate, OperationState.Failed, now), CancellationToken);

            await unitOfWork.ReconciliationRuns.RecordAsync(
                new ReconciliationRun
                {
                    Timestamp = now,
                    Completed = 1,
                    RolledBack = 0,
                    Synchronized = 1,
                    ErrorCount = 0,
                    Succeeded = true,
                },
                CancellationToken);
            await unitOfWork.CommitAsync(CancellationToken);
        }

        SqliteExecutionSummaryService summary = new(
            database.ConnectionFactory,
            new ObservabilityOptions { SummaryWindow = TimeSpan.FromHours(1) },
            TimeProvider.System);

        ExecutionSummary result = await summary.GetSummaryAsync(window: null, CancellationToken);

        Assert.Equal(4, result.Executions.Started);
        Assert.Equal(2, result.Executions.Succeeded);
        Assert.Equal(1, result.Executions.Failed);
        Assert.Equal(1, result.Executions.Running);
        Assert.Equal(2, result.Executions.Retries);

        Assert.Equal(2, result.Rejections.Total);
        Assert.Equal(1, result.Rejections.ByReason[nameof(ExecutionRejectionReason.Disabled)]);

        Assert.Equal(2, result.Schedules.Fired);
        Assert.Equal(1, result.Schedules.Missed);

        Assert.Equal(1, result.Lifecycle.Succeeded[nameof(OperationKind.Activate)]);
        Assert.Equal(1, result.Lifecycle.Failed[nameof(OperationKind.Deactivate)]);

        Assert.Equal(1, result.Reconciliation.Repaired);
        Assert.Equal(1, result.Reconciliation.Runs);
        Assert.NotNull(result.Reconciliation.LastSucceededAt);
    }

    [Fact]
    public async Task RunningCountIsCurrentWhileOutcomesAreWindowed()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);
        DateTimeOffset now = DateTimeOffset.UtcNow;

        await using (IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken))
        {
            await unitOfWork.Executions.CreateAsync(
                Execution("old-running", JobExecutionStatus.Running, attempt: 1, now.AddDays(-10)),
                CancellationToken);
            await unitOfWork.CommitAsync(CancellationToken);
        }

        SqliteExecutionSummaryService summary = new(
            database.ConnectionFactory,
            new ObservabilityOptions { SummaryWindow = TimeSpan.FromHours(1) },
            TimeProvider.System);

        ExecutionSummary result = await summary.GetSummaryAsync(window: null, CancellationToken);

        Assert.Equal(0, result.Executions.Started);
        Assert.Equal(1, result.Executions.Running);
    }

    private static ExecutionRecord Execution(string jobId, JobExecutionStatus status, int attempt, DateTimeOffset at) => new()
    {
        ExecutionId = Guid.NewGuid(),
        JobId = jobId,
        PluginId = "plugin-1",
        PluginVersion = new Version(1, 0, 0),
        ConfigurationRevision = 1,
        Attempt = attempt,
        Status = status,
        CorrelationId = Guid.NewGuid().ToString("N"),
        ScheduledAt = at,
        StartedAt = at,
    };

    private static ExecutionRejection Rejection(string jobId, ExecutionRejectionReason reason, DateTimeOffset at) => new()
    {
        Timestamp = at,
        JobId = jobId,
        PluginId = "plugin-1",
        Reason = reason,
        CorrelationId = Guid.NewGuid().ToString("N"),
    };

    private static ScheduleEvent ScheduleEvent(string jobId, ScheduleEventKind kind, DateTimeOffset at) => new()
    {
        Timestamp = at,
        JobId = jobId,
        Kind = kind,
    };

    private static OperationRecord Operation(OperationKind kind, OperationState state, DateTimeOffset at) => new()
    {
        OperationId = Guid.NewGuid(),
        Kind = kind,
        Payload = "{}",
        State = state,
        CreatedAt = at,
        UpdatedAt = at,
    };
}

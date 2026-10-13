using Scheduler.Application.Persistence;
using Scheduler.Contracts.Execution;

namespace Scheduler.Tests.Integration;

public sealed class ExecutionRepositoryTests
{
    private static readonly DateTimeOffset ScheduledAt = new(2026, 3, 4, 5, 6, 7, TimeSpan.Zero);

    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task ExecutionRoundTrips()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);

        ExecutionRecord execution = NewExecution();
        await using (IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken))
        {
            await unitOfWork.Executions.CreateAsync(execution, CancellationToken);
            await unitOfWork.CommitAsync(CancellationToken);
        }

        await using IRegistryUnitOfWork read = await database.UnitOfWorkFactory.BeginAsync(CancellationToken);
        ExecutionRecord? reloaded = await read.Executions.GetAsync(execution.ExecutionId, CancellationToken);

        Assert.Equal(execution, reloaded);
    }

    [Fact]
    public async Task UpdateAdvancesStatusAndResult()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);

        ExecutionRecord execution = NewExecution();
        await using (IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken))
        {
            await unitOfWork.Executions.CreateAsync(execution, CancellationToken);
            await unitOfWork.CommitAsync(CancellationToken);
        }

        ExecutionRecord running = execution with
        {
            Status = JobExecutionStatus.Running,
            StartedAt = ScheduledAt.AddSeconds(1),
        };
        await using (IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken))
        {
            await unitOfWork.Executions.UpdateAsync(running, CancellationToken);
            await unitOfWork.CommitAsync(CancellationToken);
        }

        ExecutionRecord succeeded = running with
        {
            Status = JobExecutionStatus.Succeeded,
            EndedAt = ScheduledAt.AddSeconds(9),
            ResultSummary = "completed",
        };
        await using (IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken))
        {
            await unitOfWork.Executions.UpdateAsync(succeeded, CancellationToken);
            await unitOfWork.CommitAsync(CancellationToken);
        }

        await using IRegistryUnitOfWork read = await database.UnitOfWorkFactory.BeginAsync(CancellationToken);
        ExecutionRecord? reloaded = await read.Executions.GetAsync(execution.ExecutionId, CancellationToken);

        Assert.Equal(succeeded, reloaded);
    }

    [Fact]
    public async Task ListsByJobAndStatus()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);

        ExecutionRecord pending = NewExecution();
        ExecutionRecord failed = pending with
        {
            ExecutionId = Guid.NewGuid(),
            Attempt = 2,
            Status = JobExecutionStatus.Failed,
            ResultSummary = "boom",
        };

        await using (IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken))
        {
            await unitOfWork.Executions.CreateAsync(pending, CancellationToken);
            await unitOfWork.Executions.CreateAsync(failed, CancellationToken);
            await unitOfWork.CommitAsync(CancellationToken);
        }

        await using IRegistryUnitOfWork read = await database.UnitOfWorkFactory.BeginAsync(CancellationToken);

        IReadOnlyList<ExecutionRecord> forJob = await read.Executions.ListByJobAsync(pending.JobId, CancellationToken);
        IReadOnlyList<ExecutionRecord> failedOnly = await read.Executions.ListByStatusAsync(JobExecutionStatus.Failed, CancellationToken);

        Assert.Equal(2, forJob.Count);
        Assert.Single(failedOnly);
        Assert.Equal(failed.ExecutionId, failedOnly[0].ExecutionId);
    }

    private static ExecutionRecord NewExecution() => new()
    {
        ExecutionId = Guid.NewGuid(),
        JobId = "monthly-report",
        PluginId = "monthly-report",
        PluginVersion = new Version(1, 2, 0),
        ConfigurationRevision = 7,
        Attempt = 1,
        Status = JobExecutionStatus.Pending,
        ScheduledAt = ScheduledAt,
    };
}

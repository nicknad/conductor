using Microsoft.Data.Sqlite;
using Scheduler.Application.Observability;
using Scheduler.Application.Persistence;
using Scheduler.Contracts.Execution;
using Scheduler.Contracts.Jobs;

namespace Scheduler.Tests.Integration.Observability;

public sealed class ObservabilityRepositoryTests
{
    private static readonly DateTimeOffset Now = new(2026, 5, 6, 7, 8, 9, TimeSpan.Zero);

    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task ExecutionCorrelationIdRoundTrips()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);

        ExecutionRecord execution = NewExecution("job-1", JobExecutionStatus.Succeeded) with { CorrelationId = "abc123" };
        await using (IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken))
        {
            await unitOfWork.Executions.CreateAsync(execution, CancellationToken);
            await unitOfWork.CommitAsync(CancellationToken);
        }

        await using IRegistryUnitOfWork read = await database.UnitOfWorkFactory.BeginAsync(CancellationToken);
        ExecutionRecord? reloaded = await read.Executions.GetAsync(execution.ExecutionId, CancellationToken);
        Assert.Equal("abc123", reloaded?.CorrelationId);
    }

    [Fact]
    public async Task ExecutionFilterSelectsByJobStatusAndWindow()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);

        await SeedExecutionsAsync(database);

        await using IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken);

        IReadOnlyList<ExecutionRecord> failed = await unitOfWork.Executions.ListAsync(
            new ExecutionFilter { Status = JobExecutionStatus.Failed },
            CancellationToken);
        Assert.Single(failed);
        Assert.Equal("job-1", failed[0].JobId);

        IReadOnlyList<ExecutionRecord> jobTwo = await unitOfWork.Executions.ListAsync(
            new ExecutionFilter { JobId = "job-2" },
            CancellationToken);
        Assert.Single(jobTwo);

        IReadOnlyList<ExecutionRecord> recent = await unitOfWork.Executions.ListAsync(
            new ExecutionFilter { Since = Now.AddMinutes(-1) },
            CancellationToken);
        Assert.Single(recent);

        IReadOnlyList<ExecutionRecord> all = await unitOfWork.Executions.ListAsync(
            new ExecutionFilter { Since = Now.AddHours(-3) },
            CancellationToken);
        Assert.Equal(2, all.Count);
    }

    [Fact]
    public async Task ExecutionFilterHonorsUntil()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);
        await SeedExecutionsAsync(database);

        await using IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken);
        IReadOnlyList<ExecutionRecord> before = await unitOfWork.Executions.ListAsync(
            new ExecutionFilter { Until = Now.AddHours(-1) },
            CancellationToken);

        ExecutionRecord only = Assert.Single(before);
        Assert.Equal("job-2", only.JobId);
    }

    [Fact]
    public async Task RunningExecutionsBecomeInterrupted()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);

        await using (IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken))
        {
            await unitOfWork.Executions.CreateAsync(NewExecution("job-1", JobExecutionStatus.Running), CancellationToken);
            await unitOfWork.Executions.CreateAsync(NewExecution("job-2", JobExecutionStatus.Succeeded), CancellationToken);
            await unitOfWork.CommitAsync(CancellationToken);
        }

        await using (IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken))
        {
            int classified = await unitOfWork.Executions.MarkRunningAsInterruptedAsync(Now, CancellationToken);
            await unitOfWork.CommitAsync(CancellationToken);
            Assert.Equal(1, classified);
        }

        // Idempotent: a second pass classifies nothing.
        await using (IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken))
        {
            Assert.Equal(0, await unitOfWork.Executions.MarkRunningAsInterruptedAsync(Now.AddMinutes(1), CancellationToken));
            await unitOfWork.CommitAsync(CancellationToken);
        }

        await using IRegistryUnitOfWork read = await database.UnitOfWorkFactory.BeginAsync(CancellationToken);
        IReadOnlyList<ExecutionRecord> interrupted = await read.Executions.ListByStatusAsync(JobExecutionStatus.Interrupted, CancellationToken);
        Assert.Single(interrupted);
        Assert.NotNull(interrupted[0].EndedAt);
    }

    [Fact]
    public async Task RejectionsRecordAndCountByReason()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);

        await using (IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken))
        {
            await unitOfWork.Rejections.RecordAsync(NewRejection("job-1", ExecutionRejectionReason.Disabled, "c1"), CancellationToken);
            await unitOfWork.Rejections.RecordAsync(NewRejection("job-1", ExecutionRejectionReason.Disabled, "c2"), CancellationToken);
            await unitOfWork.Rejections.RecordAsync(NewRejection("job-2", ExecutionRejectionReason.NoActiveVersion, "c3"), CancellationToken);
            await unitOfWork.CommitAsync(CancellationToken);
        }

        await using IRegistryUnitOfWork read = await database.UnitOfWorkFactory.BeginAsync(CancellationToken);
        IReadOnlyDictionary<ExecutionRejectionReason, int> counts = await read.Rejections.CountByReasonAsync(since: null, CancellationToken);

        Assert.Equal(2, counts[ExecutionRejectionReason.Disabled]);
        Assert.Equal(1, counts[ExecutionRejectionReason.NoActiveVersion]);

        IReadOnlyList<ExecutionRejection> listed = await read.Rejections.ListAsync(since: null, limit: 10, CancellationToken);
        Assert.Equal(3, listed.Count);
        Assert.Equal("c3", listed[0].CorrelationId);
        Assert.Equal("job-2", listed[0].JobId);
    }

    [Fact]
    public async Task ScheduleEventsCountByKind()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);

        await using (IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken))
        {
            await unitOfWork.ScheduleEvents.RecordAsync(NewScheduleEvent("job-1", ScheduleEventKind.Fired), CancellationToken);
            await unitOfWork.ScheduleEvents.RecordAsync(NewScheduleEvent("job-1", ScheduleEventKind.Fired), CancellationToken);
            await unitOfWork.ScheduleEvents.RecordAsync(NewScheduleEvent("job-1", ScheduleEventKind.Missed), CancellationToken);
            await unitOfWork.CommitAsync(CancellationToken);
        }

        await using IRegistryUnitOfWork read = await database.UnitOfWorkFactory.BeginAsync(CancellationToken);
        ScheduleEventCounts counts = await read.ScheduleEvents.CountAsync(since: null, CancellationToken);

        Assert.Equal(2, counts.Fired);
        Assert.Equal(1, counts.Missed);
        Assert.Equal(0, counts.Skipped);
    }

    [Fact]
    public async Task ReconciliationRunsRecordAndReturnLatest()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);

        await using (IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken))
        {
            await unitOfWork.ReconciliationRuns.RecordAsync(NewRun(succeeded: false, errorCount: 2), CancellationToken);
            await unitOfWork.ReconciliationRuns.RecordAsync(NewRun(succeeded: true, errorCount: 0), CancellationToken);
            await unitOfWork.CommitAsync(CancellationToken);
        }

        await using IRegistryUnitOfWork read = await database.UnitOfWorkFactory.BeginAsync(CancellationToken);
        ReconciliationRun? latest = await read.ReconciliationRuns.GetLatestAsync(CancellationToken);

        Assert.NotNull(latest);
        Assert.True(latest.Succeeded);
        Assert.Equal(0, latest.ErrorCount);
    }

    [Fact]
    public async Task MisfireEventResolvesTheJobsMisfirePolicy()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);

        await using (IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken))
        {
            await unitOfWork.Jobs.UpsertAsync(
                new JobRecord
                {
                    Definition = new JobDefinition
                    {
                        JobId = "job-1",
                        PluginId = "plugin-1",
                        PluginVersion = new Version(1, 0, 0),
                        Schedule = ScheduleSpec.FromCron("0 0 * * *"),
                        MisfirePolicy = MisfirePolicy.Skip,
                    },
                    ConfigurationRevision = 1,
                    UpdatedAt = Now,
                },
                CancellationToken);
            await unitOfWork.CommitAsync(CancellationToken);
        }

        ScheduleEventRecorder recorder = new(database.UnitOfWorkFactory, TimeProvider.System);
        await recorder.RecordMisfiredAsync("job-1", CancellationToken);

        await using SqliteConnection connection = await database.ConnectionFactory.OpenConnectionAsync(CancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            "SELECT misfire_policy FROM schedule_events WHERE job_id = 'job-1' AND event_kind = 'Missed';";
        object? policy = await command.ExecuteScalarAsync(CancellationToken);

        Assert.Equal(nameof(MisfirePolicy.Skip), policy);
    }

    [Fact]
    public async Task AuditFilterSelectsByActorActionAndTarget()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);

        await using (IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken))
        {
            await unitOfWork.Audit.WriteAsync(NewAudit("local", "plugin.activate", "p:1.0.0"), CancellationToken);
            await unitOfWork.Audit.WriteAsync(NewAudit("local", "job.run", "job-1"), CancellationToken);
            await unitOfWork.Audit.WriteAsync(NewAudit("reconciler", "reconcile.completed", "scheduler"), CancellationToken);
            await unitOfWork.CommitAsync(CancellationToken);
        }

        await using IRegistryUnitOfWork read = await database.UnitOfWorkFactory.BeginAsync(CancellationToken);
        IReadOnlyList<AuditEntry> entries = await read.Audit.ListAsync(
            new AuditFilter { Action = "job.run" },
            CancellationToken);

        Assert.Single(entries);
        Assert.Equal("job-1", entries[0].Target);
    }

    private static async Task SeedExecutionsAsync(SqliteTestDatabase database)
    {
        await using IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken);
        await unitOfWork.Executions.CreateAsync(NewExecution("job-1", JobExecutionStatus.Failed), CancellationToken);
        await unitOfWork.Executions.CreateAsync(
            NewExecution("job-2", JobExecutionStatus.Succeeded) with { ScheduledAt = Now.AddHours(-2) },
            CancellationToken);
        await unitOfWork.CommitAsync(CancellationToken);
    }

    private static ExecutionRecord NewExecution(string jobId, JobExecutionStatus status) => new()
    {
        ExecutionId = Guid.NewGuid(),
        JobId = jobId,
        PluginId = "plugin-1",
        PluginVersion = new Version(1, 0, 0),
        ConfigurationRevision = 1,
        Attempt = 1,
        Status = status,
        CorrelationId = "corr-" + jobId,
        ScheduledAt = Now,
    };

    private static ExecutionRejection NewRejection(string jobId, ExecutionRejectionReason reason, string correlationId) => new()
    {
        Timestamp = Now,
        JobId = jobId,
        PluginId = "plugin-1",
        Reason = reason,
        CorrelationId = correlationId,
        Details = null,
    };

    private static ScheduleEvent NewScheduleEvent(string jobId, ScheduleEventKind kind) => new()
    {
        Timestamp = Now,
        JobId = jobId,
        Kind = kind,
        MisfirePolicy = kind == ScheduleEventKind.Missed ? MisfirePolicy.Skip : null,
    };

    private static ReconciliationRun NewRun(bool succeeded, int errorCount) => new()
    {
        Timestamp = Now,
        Completed = 0,
        RolledBack = 0,
        Synchronized = succeeded ? 3 : 0,
        ErrorCount = errorCount,
        Succeeded = succeeded,
    };

    private static AuditEntry NewAudit(string actor, string action, string target) => new()
    {
        Timestamp = Now,
        Actor = actor,
        Action = action,
        Target = target,
    };
}

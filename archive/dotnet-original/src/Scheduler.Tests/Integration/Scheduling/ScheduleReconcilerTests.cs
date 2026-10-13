using Quartz;
using Scheduler.Application.Observability;
using Scheduler.Application.Persistence;
using Scheduler.Application.Reconciliation;
using Scheduler.Contracts.Execution;
using Scheduler.Contracts.Jobs;

namespace Scheduler.Tests.Integration.Scheduling;

public sealed class ScheduleReconcilerTests
{
    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task AppliesPendingScheduleChangeAndMarksItSucceeded()
    {
        await using QuartzScheduleTestContext context = await QuartzScheduleTestContext.CreateAsync(cancellationToken: CancellationToken);
        await context.SeedActivePluginAsync("plugin-1", new Version(1, 0, 0), CancellationToken);
        JobRecord job = ScheduleTestData.Record(ScheduleTestData.Definition());
        await context.SeedJobAsync(job, CancellationToken);

        Guid operationId = Guid.NewGuid();
        await context.CreateOperationAsync(
            ScheduleChangeOutbox.Create(operationId, job, ScheduleChangeAction.Create, DateTimeOffset.UnixEpoch),
            CancellationToken);

        ReconciliationResult result = await context.Reconciler.ReconcileAsync(CancellationToken);

        Assert.Empty(result.Errors);
        ScheduledJob scheduled = Assert.Single(await context.ListScheduledAsync(CancellationToken));
        Assert.Equal("job-1", scheduled.JobId);
        Assert.Equal(1, scheduled.ConfigurationRevision);
        Assert.Equal(OperationState.Succeeded, (await context.ReadOperationAsync(operationId, CancellationToken))!.State);
    }

    [Fact]
    public async Task RecoversAScheduleChangeStrandedInRunningAfterACrash()
    {
        await using QuartzScheduleTestContext context = await QuartzScheduleTestContext.CreateAsync(cancellationToken: CancellationToken);
        await context.SeedActivePluginAsync("plugin-1", new Version(1, 0, 0), CancellationToken);
        JobRecord job = ScheduleTestData.Record(ScheduleTestData.Definition());
        await context.SeedJobAsync(job, CancellationToken);

        // Simulate a crash between the "apply" mark (Running) and the "done" mark (Succeeded).
        OperationRecord operation = ScheduleChangeOutbox.Create(Guid.NewGuid(), job, ScheduleChangeAction.Create, DateTimeOffset.UnixEpoch);
        await context.CreateOperationAsync(operation, CancellationToken);
        await context.TransitionOperationAsync(operation.OperationId, OperationState.Running, CancellationToken);

        ReconciliationResult result = await context.Reconciler.ReconcileAsync(CancellationToken);

        Assert.Empty(result.Errors);
        Assert.Single(await context.ListScheduledAsync(CancellationToken));
        Assert.Equal(OperationState.Succeeded, (await context.ReadOperationAsync(operation.OperationId, CancellationToken))!.State);
    }

    [Fact]
    public async Task ResolvesALifecycleOperationLeftPendingByACrash()
    {
        await using QuartzScheduleTestContext context = await QuartzScheduleTestContext.CreateAsync(cancellationToken: CancellationToken);
        await context.SeedActivePluginAsync("plugin-1", new Version(1, 0, 0), CancellationToken);
        OperationRecord operation = ScheduleTestData.ActivationOperation("plugin-1", "1.0.0", OperationState.Pending);
        await context.CreateOperationAsync(operation, CancellationToken);

        ReconciliationResult result = await context.Reconciler.ReconcileAsync(CancellationToken);

        Assert.Empty(result.Errors);
        Assert.Equal(OperationState.Succeeded, (await context.ReadOperationAsync(operation.OperationId, CancellationToken))!.State);
    }

    [Fact]
    public async Task ApplyingTheSameProjectionTwiceHasNoEffectTheSecondTime()
    {
        await using QuartzScheduleTestContext context = await QuartzScheduleTestContext.CreateAsync(cancellationToken: CancellationToken);
        ScheduleProjection projection = new(
            "job-1",
            "plugin-1",
            "1.0.0",
            1,
            ScheduleSpec.FromInterval(TimeSpan.FromMinutes(5)),
            MisfirePolicy.FireOnce);

        await context.ScheduleStore.ApplyAsync(projection, CancellationToken);
        await context.ScheduleStore.ApplyAsync(projection, CancellationToken);

        Assert.Single(await context.ListScheduledAsync(CancellationToken));
    }

    [Fact]
    public async Task RepeatedSweepsDoNotDuplicateTriggers()
    {
        await using QuartzScheduleTestContext context = await QuartzScheduleTestContext.CreateAsync(cancellationToken: CancellationToken);
        await context.SeedActivePluginAsync("plugin-1", new Version(1, 0, 0), CancellationToken);
        JobRecord job = ScheduleTestData.Record(ScheduleTestData.Definition());
        await context.SeedJobAsync(job, CancellationToken);
        OperationRecord operation = ScheduleChangeOutbox.Create(Guid.NewGuid(), job, ScheduleChangeAction.Update, DateTimeOffset.UnixEpoch);
        await context.CreateOperationAsync(operation, CancellationToken);

        await context.Reconciler.ReconcileAsync(CancellationToken);
        await context.Reconciler.ReconcileAsync(CancellationToken);

        Assert.Single(await context.ListScheduledAsync(CancellationToken));
        Assert.Equal(OperationState.Succeeded, (await context.ReadOperationAsync(operation.OperationId, CancellationToken))!.State);
    }

    [Fact]
    public async Task ConcurrentSweepsDoNotFailAnInFlightChange()
    {
        await using QuartzScheduleTestContext context = await QuartzScheduleTestContext.CreateAsync(cancellationToken: CancellationToken);
        await context.SeedActivePluginAsync("plugin-1", new Version(1, 0, 0), CancellationToken);
        JobRecord job = ScheduleTestData.Record(ScheduleTestData.Definition());
        await context.SeedJobAsync(job, CancellationToken);
        OperationRecord operation = ScheduleChangeOutbox.Create(Guid.NewGuid(), job, ScheduleChangeAction.Create, DateTimeOffset.UnixEpoch);
        await context.CreateOperationAsync(operation, CancellationToken);

        ReconciliationResult[] results = await Task.WhenAll(
            Enumerable.Range(0, 5).Select(_ => context.Reconciler.ReconcileAsync(CancellationToken)));

        Assert.All(results, result => Assert.Empty(result.Errors));
        Assert.Single(await context.ListScheduledAsync(CancellationToken));
        Assert.Equal(OperationState.Succeeded, (await context.ReadOperationAsync(operation.OperationId, CancellationToken))!.State);
    }

    [Fact]
    public async Task SchedulesAnEnabledJobThatHasNoTrigger()
    {
        await using QuartzScheduleTestContext context = await QuartzScheduleTestContext.CreateAsync(cancellationToken: CancellationToken);
        await context.SeedActivePluginAsync("plugin-1", new Version(1, 0, 0), CancellationToken);
        await context.SeedJobAsync(ScheduleTestData.Record(ScheduleTestData.Definition()), CancellationToken);

        await context.Reconciler.ReconcileAsync(CancellationToken);

        ScheduledJob scheduled = Assert.Single(await context.ListScheduledAsync(CancellationToken));
        Assert.Equal("job-1", scheduled.JobId);
        Assert.Equal("plugin-1", scheduled.PluginId);
    }

    [Fact]
    public async Task RemovesARogueTriggerWithoutARegistryBasis()
    {
        await using QuartzScheduleTestContext context = await QuartzScheduleTestContext.CreateAsync(cancellationToken: CancellationToken);
        await context.SeedActivePluginAsync("plugin-1", new Version(1, 0, 0), CancellationToken);
        await context.SeedJobAsync(ScheduleTestData.Record(ScheduleTestData.Definition()), CancellationToken);
        await context.ScheduleStore.ApplyAsync(
            new ScheduleProjection(
                "rogue-job",
                "plugin-1",
                "1.0.0",
                1,
                ScheduleSpec.FromInterval(TimeSpan.FromMinutes(5)),
                MisfirePolicy.FireOnce),
            CancellationToken);

        await context.Reconciler.ReconcileAsync(CancellationToken);

        IReadOnlyList<ScheduledJob> scheduled = await context.ListScheduledAsync(CancellationToken);
        Assert.DoesNotContain(scheduled, job => job.JobId == "rogue-job");
        Assert.Contains(scheduled, job => job.JobId == "job-1");
    }

    [Fact]
    public async Task RemovesTheTriggerOfADisabledJobAndRestoresItOnReEnable()
    {
        await using QuartzScheduleTestContext context = await QuartzScheduleTestContext.CreateAsync(cancellationToken: CancellationToken);
        await context.SeedActivePluginAsync("plugin-1", new Version(1, 0, 0), CancellationToken);
        await context.SeedJobAsync(ScheduleTestData.Record(ScheduleTestData.Definition()), CancellationToken);
        await context.Reconciler.ReconcileAsync(CancellationToken);
        Assert.Single(await context.ListScheduledAsync(CancellationToken));

        await context.SetJobEnabledAsync("job-1", enabled: false, CancellationToken);
        await context.Reconciler.ReconcileAsync(CancellationToken);
        Assert.Empty(await context.ListScheduledAsync(CancellationToken));

        await context.SetJobEnabledAsync("job-1", enabled: true, CancellationToken);
        await context.Reconciler.ReconcileAsync(CancellationToken);
        Assert.Single(await context.ListScheduledAsync(CancellationToken));
    }

    [Fact]
    public async Task ManagerMutationAndReconcilerConvergeEndToEnd()
    {
        await using QuartzScheduleTestContext context = await QuartzScheduleTestContext.CreateAsync(cancellationToken: CancellationToken);
        await context.SeedActivePluginAsync("plugin-1", new Version(1, 0, 0), CancellationToken);
        await context.SeedJobAsync(ScheduleTestData.Record(ScheduleTestData.Definition()), CancellationToken);
        await context.Reconciler.ReconcileAsync(CancellationToken);
        Assert.Single(await context.ListScheduledAsync(CancellationToken));

        // The real job manager writes the registry row and the outbox record together.
        await context.Jobs.SetEnabledAsync("job-1", enabled: false, CancellationToken);
        await context.Reconciler.ReconcileAsync(CancellationToken);

        Assert.Empty(await context.ListScheduledAsync(CancellationToken));
    }

    [Fact]
    public async Task DeactivatingAPluginRemovesItsTriggers()
    {
        await using QuartzScheduleTestContext context = await QuartzScheduleTestContext.CreateAsync(cancellationToken: CancellationToken);
        await context.SeedActivePluginAsync("plugin-1", new Version(1, 0, 0), CancellationToken);
        await context.SeedJobAsync(ScheduleTestData.Record(ScheduleTestData.Definition()), CancellationToken);
        await context.Reconciler.ReconcileAsync(CancellationToken);
        Assert.Single(await context.ListScheduledAsync(CancellationToken));

        await context.ClearActivationAsync("plugin-1", CancellationToken);
        await context.Reconciler.ReconcileAsync(CancellationToken);

        Assert.Empty(await context.ListScheduledAsync(CancellationToken));
    }

    [Fact]
    public async Task DoesNotScheduleWhileThePluginHasNoActiveVersion()
    {
        await using QuartzScheduleTestContext context = await QuartzScheduleTestContext.CreateAsync(cancellationToken: CancellationToken);
        await context.SeedStagedPluginAsync("plugin-1", new Version(1, 0, 0), CancellationToken);
        await context.SeedJobAsync(ScheduleTestData.Record(ScheduleTestData.Definition()), CancellationToken);

        await context.Reconciler.ReconcileAsync(CancellationToken);

        Assert.Empty(await context.ListScheduledAsync(CancellationToken));
    }

    [Fact]
    public async Task RefreshesATriggerWhenTheConfigurationRevisionChanges()
    {
        await using QuartzScheduleTestContext context = await QuartzScheduleTestContext.CreateAsync(cancellationToken: CancellationToken);
        await context.SeedActivePluginAsync("plugin-1", new Version(1, 0, 0), CancellationToken);
        await context.SeedJobAsync(ScheduleTestData.Record(ScheduleTestData.Definition(), revision: 1), CancellationToken);
        await context.Reconciler.ReconcileAsync(CancellationToken);

        await context.SeedJobAsync(ScheduleTestData.Record(ScheduleTestData.Definition(), revision: 2), CancellationToken);
        await context.Reconciler.ReconcileAsync(CancellationToken);

        ScheduledJob scheduled = Assert.Single(await context.ListScheduledAsync(CancellationToken));
        Assert.Equal(2, scheduled.ConfigurationRevision);
    }

    [Fact]
    public async Task SchedulesAFutureOneShotButNotAPastOne()
    {
        await using QuartzScheduleTestContext context = await QuartzScheduleTestContext.CreateAsync(cancellationToken: CancellationToken);
        await context.SeedActivePluginAsync("plugin-1", new Version(1, 0, 0), CancellationToken);

        JobDefinition future = ScheduleTestData.Definition("future-job") with
        {
            Schedule = ScheduleSpec.FromOneShot(DateTimeOffset.UtcNow.AddHours(1)),
        };
        JobDefinition past = ScheduleTestData.Definition("past-job") with
        {
            Schedule = ScheduleSpec.FromOneShot(DateTimeOffset.UtcNow.AddMinutes(-1)),
        };
        await context.SeedJobAsync(ScheduleTestData.Record(future), CancellationToken);
        await context.SeedJobAsync(ScheduleTestData.Record(past), CancellationToken);

        await context.Reconciler.ReconcileAsync(CancellationToken);

        IReadOnlyList<ScheduledJob> scheduled = await context.ListScheduledAsync(CancellationToken);
        Assert.Contains(scheduled, job => job.JobId == "future-job");
        Assert.DoesNotContain(scheduled, job => job.JobId == "past-job");
    }

    [Fact]
    public async Task AppliesTheMappedMisfireInstructionToTheTrigger()
    {
        await using QuartzScheduleTestContext context = await QuartzScheduleTestContext.CreateAsync(cancellationToken: CancellationToken);
        await context.SeedActivePluginAsync("plugin-1", new Version(1, 0, 0), CancellationToken);
        JobDefinition definition = ScheduleTestData.Definition() with
        {
            Schedule = ScheduleSpec.FromCron("0 0 2 * * ?"),
            MisfirePolicy = MisfirePolicy.Skip,
        };
        await context.SeedJobAsync(ScheduleTestData.Record(definition), CancellationToken);

        await context.Reconciler.ReconcileAsync(CancellationToken);

        ITrigger? trigger = await context.GetTriggerAsync("job-1", CancellationToken);
        Assert.NotNull(trigger);
        Assert.Equal((int)CronTriggerMisfireInstruction.DoNothing, trigger.MisfireInstructionCode);
    }

    [Fact]
    public async Task ResumesAPublishedActivationOperation()
    {
        await using QuartzScheduleTestContext context = await QuartzScheduleTestContext.CreateAsync(cancellationToken: CancellationToken);
        await context.SeedActivePluginAsync("plugin-1", new Version(1, 0, 0), CancellationToken);
        OperationRecord operation = ScheduleTestData.ActivationOperation("plugin-1", "1.0.0");
        await context.CreateOperationAsync(operation, CancellationToken);

        await context.Reconciler.ReconcileAsync(CancellationToken);

        Assert.Equal(OperationState.Succeeded, (await context.ReadOperationAsync(operation.OperationId, CancellationToken))!.State);
    }

    [Fact]
    public async Task RollsBackAnActivationThatNeverPublished()
    {
        await using QuartzScheduleTestContext context = await QuartzScheduleTestContext.CreateAsync(cancellationToken: CancellationToken);
        await context.SeedActivePluginAsync("plugin-1", new Version(1, 0, 0), CancellationToken);
        await context.SeedStagedPluginAsync("plugin-1", new Version(2, 0, 0), CancellationToken);
        OperationRecord operation = ScheduleTestData.ActivationOperation("plugin-1", "2.0.0");
        await context.CreateOperationAsync(operation, CancellationToken);

        await context.Reconciler.ReconcileAsync(CancellationToken);

        Assert.Equal(OperationState.RolledBack, (await context.ReadOperationAsync(operation.OperationId, CancellationToken))!.State);
    }

    [Fact]
    public async Task AFiredTriggerDispatchesThroughTheDispatcher()
    {
        await using QuartzScheduleTestContext context = await QuartzScheduleTestContext.CreateAsync(cancellationToken: CancellationToken);
        await context.SeedActivePluginAsync("plugin-1", new Version(1, 0, 0), CancellationToken);
        JobDefinition definition = ScheduleTestData.Definition() with
        {
            Schedule = ScheduleSpec.FromOneShot(DateTimeOffset.UtcNow.AddSeconds(1)),
        };
        await context.SeedJobAsync(ScheduleTestData.Record(definition), CancellationToken);

        await context.Reconciler.ReconcileAsync(CancellationToken);

        string jobId = await context.Dispatcher.FirstDispatch.WaitAsync(TimeSpan.FromSeconds(30), CancellationToken);
        Assert.Equal("job-1", jobId);
    }

    [Fact]
    public async Task FiringARecordsADurableScheduleEvent()
    {
        await using QuartzScheduleTestContext context = await QuartzScheduleTestContext.CreateAsync(cancellationToken: CancellationToken);
        await context.SeedActivePluginAsync("plugin-1", new Version(1, 0, 0), CancellationToken);
        JobDefinition definition = ScheduleTestData.Definition() with
        {
            Schedule = ScheduleSpec.FromOneShot(DateTimeOffset.UtcNow.AddSeconds(1)),
        };
        await context.SeedJobAsync(ScheduleTestData.Record(definition), CancellationToken);

        await context.Reconciler.ReconcileAsync(CancellationToken);
        await context.Dispatcher.FirstDispatch.WaitAsync(TimeSpan.FromSeconds(30), CancellationToken);

        await using IRegistryUnitOfWork unitOfWork = await context.UnitOfWorkFactory.BeginAsync(CancellationToken);
        ScheduleEventCounts counts = await unitOfWork.ScheduleEvents.CountAsync(since: null, CancellationToken);
        Assert.Equal(1, counts.Fired);
    }

    [Fact]
    public async Task RecordsAReconciliationRunAndUpdatesStatus()
    {
        await using QuartzScheduleTestContext context = await QuartzScheduleTestContext.CreateAsync(cancellationToken: CancellationToken);
        await context.SeedActivePluginAsync("plugin-1", new Version(1, 0, 0), CancellationToken);
        await context.SeedJobAsync(ScheduleTestData.Record(ScheduleTestData.Definition()), CancellationToken);

        await context.Reconciler.ReconcileAsync(CancellationToken);

        await using IRegistryUnitOfWork unitOfWork = await context.UnitOfWorkFactory.BeginAsync(CancellationToken);
        ReconciliationRun? run = await unitOfWork.ReconciliationRuns.GetLatestAsync(CancellationToken);
        Assert.NotNull(run);
        Assert.True(run.Succeeded);

        Assert.NotNull(context.ReconciliationStatus.LastSucceededAt);
        Assert.Equal(0, context.ReconciliationStatus.LastErrorCount);
    }
}

using Scheduler.Application.Execution;
using Scheduler.Application.JobManagement;
using Scheduler.Application.Observability;
using Scheduler.Application.Persistence;
using Scheduler.Contracts.Execution;
using Scheduler.Contracts.Jobs;
using Scheduler.Tests.Support;

namespace Scheduler.Tests.Integration.Execution;

public sealed class JobManagerTests
{
    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task UpdateBumpsConfigurationRevision()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using RuntimeTestContext context = new(
            key.PublicKeyPath,
            new FakePluginRuntime(new ScriptedJobHandler((_, _) => Task.FromResult(JobResult.Succeeded()))));
        await context.InitializeAsync(CancellationToken);
        await context.SeedActivePluginAsync("test-plugin", new Version(1, 0, 0), Definition(), CancellationToken);

        await context.Jobs.UpdateAsync(Definition() with { Timeout = TimeSpan.FromSeconds(45) }, CancellationToken);

        Assert.Equal(2, await ReadRevisionAsync(context));
    }

    [Fact]
    public async Task UpdateRejectsInvalidDefinition()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using RuntimeTestContext context = new(
            key.PublicKeyPath,
            new FakePluginRuntime(new ScriptedJobHandler((_, _) => Task.FromResult(JobResult.Succeeded()))));
        await context.InitializeAsync(CancellationToken);

        await Assert.ThrowsAsync<JobValidationException>(
            () => context.Jobs.UpdateAsync(Definition() with { JobId = string.Empty }, CancellationToken));
    }

    [Fact]
    public async Task SetEnabledTogglesSchedulingWithoutChangingTheRevision()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using RuntimeTestContext context = new(
            key.PublicKeyPath,
            new FakePluginRuntime(new ScriptedJobHandler((_, _) => Task.FromResult(JobResult.Succeeded()))));
        await context.InitializeAsync(CancellationToken);
        await context.SeedActivePluginAsync("test-plugin", new Version(1, 0, 0), Definition(), CancellationToken);

        await context.Jobs.SetEnabledAsync("test-job", enabled: false, CancellationToken);

        JobDefinition? job = await context.Jobs.GetAsync("test-job", CancellationToken);
        Assert.NotNull(job);
        Assert.False(job.Enabled);
        Assert.Equal(1, await ReadRevisionAsync(context));
    }

    [Fact]
    public async Task RunNowDispatchesThroughTheDispatcher()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using RuntimeTestContext context = new(
            key.PublicKeyPath,
            new FakePluginRuntime(new ScriptedJobHandler((_, _) => Task.FromResult(JobResult.Succeeded()))));
        await context.InitializeAsync(CancellationToken);
        await context.SeedActivePluginAsync("test-plugin", new Version(1, 0, 0), Definition(), CancellationToken);

        Guid executionId = await context.Jobs.RunNowAsync("test-job", CancellationToken);

        ExecutionRecord? execution = await context.ReadExecutionAsync(executionId, CancellationToken);
        Assert.NotNull(execution);
        Assert.Equal(JobExecutionStatus.Succeeded, execution.Status);
    }

    [Fact]
    public async Task RunNowRecordsAManualRunAuditEntry()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using RuntimeTestContext context = new(
            key.PublicKeyPath,
            new FakePluginRuntime(new ScriptedJobHandler((_, _) => Task.FromResult(JobResult.Succeeded()))));
        await context.InitializeAsync(CancellationToken);
        await context.SeedActivePluginAsync("test-plugin", new Version(1, 0, 0), Definition(), CancellationToken);

        Guid executionId = await context.Jobs.RunNowAsync("test-job", CancellationToken);

        await using IRegistryUnitOfWork unitOfWork = await context.UnitOfWorkFactory.BeginAsync(CancellationToken);
        IReadOnlyList<AuditEntry> entries = await unitOfWork.Audit.ListAsync(
            new AuditFilter { Action = "job.run" },
            CancellationToken);
        AuditEntry entry = Assert.Single(entries);
        Assert.Equal("test-job", entry.Target);
        Assert.Contains(executionId.ToString("D"), entry.Details ?? string.Empty, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RejectedRunRecordsARejectedAuditEntry()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using RuntimeTestContext context = new(
            key.PublicKeyPath,
            new FakePluginRuntime(new ScriptedJobHandler((_, _) => Task.FromResult(JobResult.Succeeded()))));
        await context.InitializeAsync(CancellationToken);
        await context.SeedActivePluginAsync(
            "test-plugin",
            new Version(1, 0, 0),
            Definition() with { Enabled = false },
            CancellationToken);

        await Assert.ThrowsAsync<DispatchRejectedException>(
            () => context.Jobs.RunNowAsync("test-job", CancellationToken));

        await using IRegistryUnitOfWork unitOfWork = await context.UnitOfWorkFactory.BeginAsync(CancellationToken);
        IReadOnlyList<AuditEntry> entries = await unitOfWork.Audit.ListAsync(
            new AuditFilter { Action = "job.run.rejected" },
            CancellationToken);
        AuditEntry entry = Assert.Single(entries);
        Assert.Equal("test-job", entry.Target);
        Assert.Contains("Disabled", entry.Details ?? string.Empty, StringComparison.Ordinal);
    }

    private static async Task<int> ReadRevisionAsync(RuntimeTestContext context)
    {
        await using IRegistryUnitOfWork unitOfWork = await context.UnitOfWorkFactory.BeginAsync(CancellationToken);
        JobRecord? job = await unitOfWork.Jobs.GetAsync("test-job", CancellationToken);
        Assert.NotNull(job);
        return job.ConfigurationRevision;
    }

    private static JobDefinition Definition() => new()
    {
        JobId = "test-job",
        PluginId = "test-plugin",
        PluginVersion = new Version(1, 0, 0),
        Schedule = ScheduleSpec.FromCron("0 0 * * *"),
    };
}

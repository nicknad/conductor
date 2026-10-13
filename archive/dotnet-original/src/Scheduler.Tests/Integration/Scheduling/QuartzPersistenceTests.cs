using Scheduler.Application.Reconciliation;

namespace Scheduler.Tests.Integration.Scheduling;

public sealed class QuartzPersistenceTests
{
    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task PersistentStoreProvisionsTheQuartzSchemaWithoutDisturbingTheRegistrySchema()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);
        int registryVersion = await database.Initializer.GetSchemaVersionAsync(CancellationToken);

        await using QuartzScheduleTestContext context = await QuartzScheduleTestContext.CreateAsync(
            database,
            ownsDatabase: false,
            persistent: true,
            cancellationToken: CancellationToken);

        IReadOnlyList<string> tables = await context.ListQuartzTablesAsync(CancellationToken);
        Assert.Contains("QRTZ_JOB_DETAILS", tables);
        Assert.Contains("QRTZ_TRIGGERS", tables);

        Assert.Equal(registryVersion, await database.Initializer.GetSchemaVersionAsync(CancellationToken));

        // Re-running the registry migrations after Quartz provisioning must be a no-op.
        await database.InitializeAsync(CancellationToken);
    }

    [Fact]
    public async Task ATriggerSurvivesASchedulerRestart()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);

        await using (QuartzScheduleTestContext first = await QuartzScheduleTestContext.CreateAsync(
            database,
            ownsDatabase: false,
            persistent: true,
            cancellationToken: CancellationToken))
        {
            await first.SeedActivePluginAsync("plugin-1", new Version(1, 0, 0), CancellationToken);
            await first.SeedJobAsync(ScheduleTestData.Record(ScheduleTestData.Definition()), CancellationToken);
            await first.Reconciler.ReconcileAsync(CancellationToken);
            Assert.Single(await first.ListScheduledAsync(CancellationToken));
        }

        await using QuartzScheduleTestContext second = await QuartzScheduleTestContext.CreateAsync(
            database,
            ownsDatabase: false,
            persistent: true,
            cancellationToken: CancellationToken);

        ScheduledJob scheduled = Assert.Single(await second.ListScheduledAsync(CancellationToken));
        Assert.Equal("job-1", scheduled.JobId);
    }

    [Fact]
    public async Task PersistedTriggerJobDataIsStringOnly()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);

        await using QuartzScheduleTestContext context = await QuartzScheduleTestContext.CreateAsync(
            database,
            ownsDatabase: false,
            persistent: true,
            cancellationToken: CancellationToken);
        await context.SeedActivePluginAsync("plugin-1", new Version(1, 0, 0), CancellationToken);
        await context.SeedJobAsync(ScheduleTestData.Record(ScheduleTestData.Definition()), CancellationToken);
        await context.Reconciler.ReconcileAsync(CancellationToken);

        IReadOnlyList<string?> raw = await context.ReadRawTriggerJobDataAsync(CancellationToken);
        string persisted = string.Join("\n", raw.Where(value => value is not null));

        Assert.Contains("jobId", persisted, StringComparison.Ordinal);
        Assert.Contains("pluginId", persisted, StringComparison.Ordinal);
        Assert.Contains("revision", persisted, StringComparison.Ordinal);
        Assert.DoesNotContain("Version=", persisted, StringComparison.Ordinal);
        Assert.DoesNotContain("Culture=", persisted, StringComparison.Ordinal);
    }
}

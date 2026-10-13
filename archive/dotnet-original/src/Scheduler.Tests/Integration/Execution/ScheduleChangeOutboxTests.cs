using Scheduler.Application.Persistence;
using Scheduler.Application.PluginManagement;
using Scheduler.Application.Reconciliation;
using Scheduler.Contracts.Execution;
using Scheduler.Contracts.Jobs;
using Scheduler.Tests.Support;

namespace Scheduler.Tests.Integration.Execution;

/// <summary>
/// Verifies that the plugin and job managers publish durable <c>ScheduleChange</c>
/// outbox records for every scheduling-relevant change, instead of touching Quartz.
/// </summary>
public sealed class ScheduleChangeOutboxTests
{
    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task JobUpdatePublishesAnUpdateChange()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using RuntimeTestContext context = new(key.PublicKeyPath);
        await context.InitializeAsync(CancellationToken);
        await context.SeedActivePluginAsync("test-plugin", new Version(1, 0, 0), Definition(), CancellationToken);

        await context.Jobs.UpdateAsync(
            Definition() with { Schedule = ScheduleSpec.FromCron("0 0 2 * * ?") },
            CancellationToken);

        ScheduleChangePayload payload = await RequireSingleScheduleChangeAsync(context);
        Assert.Equal("test-job", payload.JobId);
        Assert.Equal(ScheduleChangeAction.Update, payload.Action);
        Assert.Equal(MisfirePolicy.FireOnce, payload.MisfirePolicy);
    }

    [Fact]
    public async Task DisablingAJobPublishesAPauseChange()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using RuntimeTestContext context = new(key.PublicKeyPath);
        await context.InitializeAsync(CancellationToken);
        await context.SeedActivePluginAsync("test-plugin", new Version(1, 0, 0), Definition(), CancellationToken);

        await context.Jobs.SetEnabledAsync("test-job", enabled: false, CancellationToken);

        ScheduleChangePayload payload = await RequireSingleScheduleChangeAsync(context);
        Assert.Equal(ScheduleChangeAction.Pause, payload.Action);
        Assert.False(payload.Enabled);
    }

    [Fact]
    public async Task ActivatingAPluginPublishesChangesForItsJobs()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using RuntimeTestContext context = new(key.PublicKeyPath);
        await context.InitializeAsync(CancellationToken);

        byte[] package = TestPluginPackage.Create(
            "test-plugin",
            "Scheduler.Tests.TestPlugins.TestJobPlugin",
            new Version(1, 0, 0),
            key);
        PluginOperation install = await context.Manager.InstallAsync(new MemoryStream(package), CancellationToken);
        Assert.Equal(PluginOperationStatus.Succeeded, install.Status);

        await context.Manager.ActivateAsync("test-plugin", new Version(1, 0, 0), CancellationToken);

        ScheduleChangePayload payload = await RequireSingleScheduleChangeAsync(context);
        Assert.Equal("test-job", payload.JobId);
        Assert.Equal(ScheduleChangeAction.Create, payload.Action);
        Assert.True(payload.Enabled);
    }

    private static async Task<ScheduleChangePayload> RequireSingleScheduleChangeAsync(RuntimeTestContext context)
    {
        await using IRegistryUnitOfWork unitOfWork = await context.UnitOfWorkFactory.BeginAsync(CancellationToken);
        IReadOnlyList<OperationRecord> pending =
            await unitOfWork.Operations.ListByStateAsync(OperationState.Pending, CancellationToken);

        OperationRecord operation = Assert.Single(pending, candidate => candidate.Kind == OperationKind.ScheduleChange);
        return OperationPayloadCodec.Deserialize<ScheduleChangePayload>(operation.Payload);
    }

    private static JobDefinition Definition() => new()
    {
        JobId = "test-job",
        PluginId = "test-plugin",
        PluginVersion = new Version(1, 0, 0),
        Enabled = true,
        Schedule = ScheduleSpec.FromInterval(TimeSpan.FromMinutes(5)),
    };
}

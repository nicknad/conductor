using Scheduler.Application.Persistence;
using Scheduler.Application.PluginManagement;
using Scheduler.Contracts.Execution;
using Scheduler.Contracts.Jobs;
using Scheduler.Tests.Support;

namespace Scheduler.Tests.Integration.Execution;

public sealed class PluginActivationTests
{
    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task InstallsActivatesRunsAndDrainsEndToEnd()
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

        PluginOperation activate = await context.Manager.ActivateAsync("test-plugin", new Version(1, 0, 0), CancellationToken);
        Assert.Equal(PluginOperationStatus.Succeeded, activate.Status);
        Assert.True(context.Runtime.IsLoaded("test-plugin", new Version(1, 0, 0)));

        PluginActivationRecord activation = await RequireActivationAsync(context);
        Assert.Equal(new Version(1, 0, 0), activation.Version);

        PluginVersionRecord version = await RequireVersionAsync(context, "test-plugin", new Version(1, 0, 0));
        Assert.Equal(PluginLifecycleState.Active, version.State);

        Guid executionId = await context.Dispatcher.DispatchAsync("test-job", CancellationToken);
        ExecutionRecord execution = await RequireExecutionAsync(context, executionId);
        Assert.Equal(JobExecutionStatus.Succeeded, execution.Status);

        PluginOperation deactivate = await context.Manager.DeactivateAsync("test-plugin", CancellationToken);
        Assert.Equal(PluginOperationStatus.Succeeded, deactivate.Status);
        Assert.False(context.Runtime.IsLoaded("test-plugin", new Version(1, 0, 0)));

        PluginVersionRecord drained = await RequireVersionAsync(context, "test-plugin", new Version(1, 0, 0));
        Assert.Equal(PluginLifecycleState.Retired, drained.State);
    }

    [Fact]
    public async Task ActivatingUnknownVersionFails()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using RuntimeTestContext context = new(key.PublicKeyPath);
        await context.InitializeAsync(CancellationToken);

        PluginOperation operation = await context.Manager.ActivateAsync(
            "missing-plugin",
            new Version(1, 0, 0),
            CancellationToken);

        Assert.Equal(PluginOperationStatus.Failed, operation.Status);
    }

    [Fact]
    public async Task ActivatingAStagedVersionPublishesItsJobs()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using RuntimeTestContext context = new(key.PublicKeyPath);
        await context.InitializeAsync(CancellationToken);

        byte[] package = TestPluginPackage.Create(
            "test-plugin",
            "Scheduler.Tests.TestPlugins.TestJobPlugin",
            new Version(1, 0, 0),
            key);
        await context.Manager.InstallAsync(new MemoryStream(package), CancellationToken);
        await context.Manager.ActivateAsync("test-plugin", new Version(1, 0, 0), CancellationToken);

        IReadOnlyList<JobDefinition> jobs = await context.Jobs.ListAsync(CancellationToken);

        JobDefinition job = Assert.Single(jobs);
        Assert.Equal("test-job", job.JobId);
        Assert.Equal(new Version(1, 0, 0), job.PluginVersion);
    }

    [Fact]
    public async Task InvalidDefinitionFailsActivationAndMarksVersionFailed()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using RuntimeTestContext context = new(key.PublicKeyPath);
        await context.InitializeAsync(CancellationToken);

        await InstallAndActivateAsync(
            context,
            key,
            "invalid-definition-plugin",
            "Scheduler.Tests.TestPlugins.InvalidDefinitionJobPlugin",
            new Version(1, 0, 0),
            expectSuccess: false);

        PluginVersionRecord version = await RequireVersionAsync(
            context, "invalid-definition-plugin", new Version(1, 0, 0));
        Assert.Equal(PluginLifecycleState.Failed, version.State);
        Assert.False(context.Runtime.IsLoaded("invalid-definition-plugin", new Version(1, 0, 0)));
    }

    [Fact]
    public async Task PluginWithoutHandlerFailsActivation()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using RuntimeTestContext context = new(key.PublicKeyPath);
        await context.InitializeAsync(CancellationToken);

        await InstallAndActivateAsync(
            context,
            key,
            "no-handler-plugin",
            "Scheduler.Tests.TestPlugins.NoHandlerJobPlugin",
            new Version(1, 0, 0),
            expectSuccess: false);

        PluginVersionRecord version = await RequireVersionAsync(
            context, "no-handler-plugin", new Version(1, 0, 0));
        Assert.Equal(PluginLifecycleState.Failed, version.State);
    }

    [Fact]
    public async Task MissingEntryTypeFailsActivation()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using RuntimeTestContext context = new(key.PublicKeyPath);
        await context.InitializeAsync(CancellationToken);

        await InstallAndActivateAsync(
            context,
            key,
            "test-plugin",
            "Scheduler.Tests.TestPlugins.DoesNotExist",
            new Version(1, 0, 0),
            expectSuccess: false);

        PluginVersionRecord version = await RequireVersionAsync(context, "test-plugin", new Version(1, 0, 0));
        Assert.Equal(PluginLifecycleState.Failed, version.State);
    }

    [Fact]
    public async Task RepeatedActivationIsIdempotent()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using RuntimeTestContext context = new(key.PublicKeyPath);
        await context.InitializeAsync(CancellationToken);
        await InstallAndActivateAsync(
            context,
            key,
            "test-plugin",
            "Scheduler.Tests.TestPlugins.TestJobPlugin",
            new Version(1, 0, 0));

        PluginOperation second = await context.Manager.ActivateAsync(
            "test-plugin",
            new Version(1, 0, 0),
            CancellationToken);

        Assert.Equal(PluginOperationStatus.Succeeded, second.Status);
    }

    [Fact]
    public async Task RepeatedDeactivationIsIdempotent()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using RuntimeTestContext context = new(key.PublicKeyPath);
        await context.InitializeAsync(CancellationToken);
        await InstallAndActivateAsync(
            context,
            key,
            "test-plugin",
            "Scheduler.Tests.TestPlugins.TestJobPlugin",
            new Version(1, 0, 0));

        PluginOperation first = await context.Manager.DeactivateAsync("test-plugin", CancellationToken);
        PluginOperation second = await context.Manager.DeactivateAsync("test-plugin", CancellationToken);

        Assert.Equal(PluginOperationStatus.Succeeded, first.Status);
        Assert.Equal(PluginOperationStatus.Succeeded, second.Status);
    }

    [Fact]
    public async Task RollbackRestoresTheRetainedPreviousVersion()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using RuntimeTestContext context = new(key.PublicKeyPath);
        await context.InitializeAsync(CancellationToken);
        await InstallAndActivateAsync(
            context,
            key,
            "test-plugin",
            "Scheduler.Tests.TestPlugins.TestJobPlugin",
            new Version(1, 0, 0));
        await InstallAndActivateAsync(
            context,
            key,
            "test-plugin",
            "Scheduler.Tests.TestPlugins.TestJobPluginV2",
            new Version(2, 0, 0));

        PluginOperation rollback = await context.Manager.RollbackAsync(
            "test-plugin",
            new Version(1, 0, 0),
            CancellationToken);

        Assert.Equal(PluginOperationStatus.Succeeded, rollback.Status);
        PluginActivationRecord activation = await RequireActivationAsync(context);
        Assert.Equal(new Version(1, 0, 0), activation.Version);
        Assert.Equal(PluginLifecycleState.Active, (await RequireVersionAsync(context, "test-plugin", new Version(1, 0, 0))).State);

        Guid executionId = await context.Dispatcher.DispatchAsync("test-job", CancellationToken);
        ExecutionRecord execution = await RequireExecutionAsync(context, executionId);
        Assert.Equal(JobExecutionStatus.Succeeded, execution.Status);
        Assert.Equal(new Version(1, 0, 0), execution.PluginVersion);
    }

    private static async Task InstallAndActivateAsync(
        RuntimeTestContext context,
        TestPackageKey key,
        string pluginId,
        string entryType,
        Version version,
        bool expectSuccess = true)
    {
        byte[] package = TestPluginPackage.Create(pluginId, entryType, version, key);
        PluginOperation install = await context.Manager.InstallAsync(new MemoryStream(package), CancellationToken);
        Assert.Equal(PluginOperationStatus.Succeeded, install.Status);

        PluginOperation activate = await context.Manager.ActivateAsync(pluginId, version, CancellationToken);
        Assert.Equal(
            expectSuccess ? PluginOperationStatus.Succeeded : PluginOperationStatus.Failed,
            activate.Status);
    }

    private static async Task<PluginActivationRecord> RequireActivationAsync(RuntimeTestContext context)
    {
        PluginActivationRecord? activation = await context.ReadActivationAsync("test-plugin", CancellationToken);
        Assert.NotNull(activation);
        return activation;
    }

    private static async Task<PluginVersionRecord> RequireVersionAsync(
        RuntimeTestContext context,
        string pluginId,
        Version version)
    {
        PluginVersionRecord? record = await context.ReadVersionAsync(pluginId, version, CancellationToken);
        Assert.NotNull(record);
        return record;
    }

    private static async Task<ExecutionRecord> RequireExecutionAsync(RuntimeTestContext context, Guid executionId)
    {
        ExecutionRecord? execution = await context.ReadExecutionAsync(executionId, CancellationToken);
        Assert.NotNull(execution);
        return execution;
    }
}

using Scheduler.Application.Execution;
using Scheduler.Application.Persistence;
using Scheduler.Application.PluginManagement;
using Scheduler.Contracts.Execution;
using Scheduler.Contracts.Jobs;
using Scheduler.Tests.Support;

namespace Scheduler.Tests.Integration.Execution;

public sealed class UnloadTests
{
    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task CleanUnloadRetiresTheVersion()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using RuntimeTestContext context = new(key.PublicKeyPath);
        await context.InitializeAsync(CancellationToken);

        await InstallAndActivateAsync(
            context,
            key,
            "test-plugin",
            "Scheduler.Tests.TestPlugins.TestJobPlugin");

        PluginOperation operation = await context.Manager.DeactivateAsync("test-plugin", CancellationToken);

        Assert.True(operation.Status == PluginOperationStatus.Succeeded, operation.Error);
        PluginVersionRecord version = await RequireVersionAsync(context, "test-plugin", new Version(1, 0, 0));
        Assert.Equal(PluginLifecycleState.Retired, version.State);
        Assert.Null(version.UncleanUnloadReason);
        Assert.False(context.Runtime.IsLoaded("test-plugin", new Version(1, 0, 0)));
    }

    [Fact]
    public async Task CooperativeUnloadFailureIsSurfaced()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using RuntimeTestContext context = new(key.PublicKeyPath);
        await context.InitializeAsync(CancellationToken);

        await InstallAndActivateAsync(
            context,
            key,
            "retaining-plugin",
            "Scheduler.Tests.TestPlugins.RetainingJobPlugin");

        PluginOperation operation = await context.Manager.DeactivateAsync("retaining-plugin", CancellationToken);

        Assert.Equal(PluginOperationStatus.Failed, operation.Status);
        PluginVersionRecord version = await RequireVersionAsync(context, "retaining-plugin", new Version(1, 0, 0));
        Assert.NotEqual(PluginLifecycleState.Retired, version.State);
        Assert.NotNull(version.UncleanUnloadReason);
    }

    [Fact]
    public async Task RemoveRefusesWhenUnloadIsIncomplete()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using RuntimeTestContext context = new(key.PublicKeyPath);
        await context.InitializeAsync(CancellationToken);

        await InstallAndActivateAsync(
            context,
            key,
            "retaining-plugin",
            "Scheduler.Tests.TestPlugins.RetainingJobPlugin");

        PluginOperation operation = await context.Manager.RemoveAsync("retaining-plugin", CancellationToken);

        Assert.Equal(PluginOperationStatus.Failed, operation.Status);
        PluginVersionRecord version = await RequireVersionAsync(context, "retaining-plugin", new Version(1, 0, 0));
        Assert.NotEqual(PluginLifecycleState.Removed, version.State);
        Assert.NotNull(version.UncleanUnloadReason);
    }

    [Fact]
    public async Task CancelDrainPolicyCancelsRunningExecutions()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using RuntimeTestContext context = new(
            key.PublicKeyPath,
            executionOptions: new ExecutionOptions
            {
                DrainPolicy = DrainPolicy.Cancel,
                DrainTimeout = TimeSpan.FromSeconds(10),
            });
        await context.InitializeAsync(CancellationToken);
        await InstallAndActivateAsync(
            context,
            key,
            "test-plugin",
            "Scheduler.Tests.TestPlugins.TestJobPlugin");
        await SetLongRunningAsync(context, "test-job", sleepMilliseconds: 30_000);

        Task<Guid> dispatch = context.Dispatcher.DispatchAsync("test-job", CancellationToken);
        await WaitForRunningAsync(context);

        PluginOperation deactivate = await context.Manager.DeactivateAsync("test-plugin", CancellationToken);

        Assert.Equal(PluginOperationStatus.Succeeded, deactivate.Status);
        Guid executionId = await dispatch;
        ExecutionRecord execution = await RequireExecutionAsync(context, executionId);
        Assert.Equal(JobExecutionStatus.Cancelled, execution.Status);

        PluginVersionRecord version = await RequireVersionAsync(context, "test-plugin", new Version(1, 0, 0));
        Assert.Equal(PluginLifecycleState.Retired, version.State);
    }

    [Fact]
    public async Task VersionReplacementDoesNotAffectRunningExecution()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using RuntimeTestContext context = new(key.PublicKeyPath);
        await context.InitializeAsync(CancellationToken);
        await InstallAndActivateAsync(
            context,
            key,
            "test-plugin",
            "Scheduler.Tests.TestPlugins.TestJobPlugin");
        await SetLongRunningAsync(context, "test-job", sleepMilliseconds: 800);

        Task<Guid> dispatch = context.Dispatcher.DispatchAsync("test-job", CancellationToken);
        await WaitForRunningAsync(context);

        await InstallAndActivateAsync(
            context,
            key,
            "test-plugin",
            "Scheduler.Tests.TestPlugins.TestJobPluginV2",
            new Version(2, 0, 0));

        Guid executionId = await dispatch;
        ExecutionRecord execution = await RequireExecutionAsync(context, executionId);
        Assert.Equal(JobExecutionStatus.Succeeded, execution.Status);
        Assert.Equal(new Version(1, 0, 0), execution.PluginVersion);

        Guid second = await context.Dispatcher.DispatchAsync("test-job", CancellationToken);
        ExecutionRecord secondExecution = await RequireExecutionAsync(context, second);
        Assert.Equal(new Version(2, 0, 0), secondExecution.PluginVersion);
    }

    private static async Task SetLongRunningAsync(RuntimeTestContext context, string jobId, int sleepMilliseconds)
    {
        JobDefinition definition = (await context.Jobs.GetAsync(jobId, CancellationToken))!;
        await context.Jobs.UpdateAsync(
            definition with
            {
                Parameters = new Dictionary<string, string?>(StringComparer.Ordinal)
                {
                    ["behavior"] = "sleep",
                    ["sleepMs"] = sleepMilliseconds.ToString(System.Globalization.CultureInfo.InvariantCulture),
                },
            },
            CancellationToken);
    }

    private static async Task WaitForRunningAsync(RuntimeTestContext context)
    {
        for (int attempt = 0; attempt < 200; attempt++)
        {
            if (context.RunningExecutions.ListForPlugin("test-plugin").Count > 0)
            {
                return;
            }

            await Task.Delay(10, CancellationToken);
        }

        throw new InvalidOperationException("The execution did not start.");
    }

    private static async Task InstallAndActivateAsync(
        RuntimeTestContext context,
        TestPackageKey key,
        string pluginId,
        string entryType,
        Version? version = null)
    {
        Version target = version ?? new Version(1, 0, 0);
        byte[] package = TestPluginPackage.Create(pluginId, entryType, target, key);
        PluginOperation install = await context.Manager.InstallAsync(new MemoryStream(package), CancellationToken);
        Assert.Equal(PluginOperationStatus.Succeeded, install.Status);

        PluginOperation activate = await context.Manager.ActivateAsync(pluginId, target, CancellationToken);
        Assert.Equal(PluginOperationStatus.Succeeded, activate.Status);
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

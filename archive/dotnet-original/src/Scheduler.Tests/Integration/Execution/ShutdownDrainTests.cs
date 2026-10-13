using Scheduler.Application.Execution;
using Scheduler.Application.Observability;
using Scheduler.Application.Persistence;
using Scheduler.Contracts.Execution;
using Scheduler.Contracts.Jobs;
using Scheduler.Tests.Support;

namespace Scheduler.Tests.Integration.Execution;

public sealed class ShutdownDrainTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task WaitPolicyLetsAnInFlightExecutionComplete()
    {
        ExecutionOptions options = new() { DrainPolicy = DrainPolicy.Wait, DrainTimeout = TimeSpan.FromSeconds(5) };
        RunningExecutionRegistry registry = new(TimeProvider.System);
        ExecutionDrainer drainer = new(registry, options);

        IRunningExecution running = registry.Register(Guid.NewGuid(), "plugin-1", new Version(1, 0, 0), CancellationToken.None);
        Task completion = Task.Run(
            async () =>
            {
                await Task.Delay(100, Ct);
                running.Dispose();
            },
            Ct);

        Assert.True(await drainer.DrainAsync(Ct));
        await completion;
    }

    [Fact]
    public async Task CancelPolicyCancelsRunningExecutions()
    {
        ExecutionOptions options = new() { DrainPolicy = DrainPolicy.Cancel, DrainTimeout = TimeSpan.FromSeconds(5) };
        RunningExecutionRegistry registry = new(TimeProvider.System);
        ExecutionDrainer drainer = new(registry, options);

        IRunningExecution running = registry.Register(Guid.NewGuid(), "plugin-1", new Version(1, 0, 0), CancellationToken.None);
        Task completion = Task.Run(
            async () =>
            {
                try
                {
                    await Task.Delay(Timeout.InfiniteTimeSpan, running.Token);
                }
                catch (OperationCanceledException)
                {
                }

                running.Dispose();
            },
            Ct);

        Assert.True(await drainer.DrainAsync(Ct));
        await completion;
        Assert.NotNull(running.CancellationReason);
    }

    [Fact]
    public async Task DrainTimesOutWhenAnExecutionDoesNotFinish()
    {
        ExecutionOptions options = new() { DrainPolicy = DrainPolicy.Wait, DrainTimeout = TimeSpan.FromMilliseconds(50) };
        RunningExecutionRegistry registry = new(TimeProvider.System);
        ExecutionDrainer drainer = new(registry, options);

        using IRunningExecution running = registry.Register(Guid.NewGuid(), "plugin-1", new Version(1, 0, 0), CancellationToken.None);

        Assert.False(await drainer.DrainAsync(Ct));
    }

    [Fact]
    public async Task DispatcherStopsAcceptingFireTimesOnceShutdownBegins()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using RuntimeTestContext context = new(
            key.PublicKeyPath,
            new FakePluginRuntime(new ScriptedJobHandler((_, _) => Task.FromResult(JobResult.Succeeded()))));
        await context.InitializeAsync(Ct);
        await context.SeedActivePluginAsync("test-plugin", new Version(1, 0, 0), Definition(), Ct);

        context.Shutdown.BeginShutdown();

        DispatchRejectedException exception = await Assert.ThrowsAsync<DispatchRejectedException>(
            () => context.Dispatcher.DispatchAsync("test-job", Ct));
        Assert.Equal(ExecutionRejectionReason.ShuttingDown, exception.Reason);
    }

    [Fact]
    public async Task ShuttingDownRejectionIsRecordedDurably()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using RuntimeTestContext context = new(
            key.PublicKeyPath,
            new FakePluginRuntime(new ScriptedJobHandler((_, _) => Task.FromResult(JobResult.Succeeded()))));
        await context.InitializeAsync(Ct);
        await context.SeedActivePluginAsync("test-plugin", new Version(1, 0, 0), Definition(), Ct);

        context.Shutdown.BeginShutdown();

        await Assert.ThrowsAsync<DispatchRejectedException>(() => context.Dispatcher.DispatchAsync("test-job", Ct));

        await using IRegistryUnitOfWork unitOfWork = await context.UnitOfWorkFactory.BeginAsync(Ct);
        IReadOnlyList<ExecutionRejection> rejections = await unitOfWork.Rejections.ListAsync(
            since: null,
            limit: 10,
            Ct);
        Assert.Contains(rejections, rejection => rejection.Reason == ExecutionRejectionReason.ShuttingDown);
    }

    private static JobDefinition Definition() => new()
    {
        JobId = "test-job",
        PluginId = "test-plugin",
        PluginVersion = new Version(1, 0, 0),
        Schedule = ScheduleSpec.FromCron("0 0 * * *"),
    };
}

using Scheduler.Application.Execution;
using Scheduler.Application.Observability;
using Scheduler.Application.Persistence;
using Scheduler.Contracts.Execution;
using Scheduler.Contracts.Jobs;
using Scheduler.Tests.Support;

namespace Scheduler.Tests.Integration.Execution;

public sealed class DispatcherTests
{
    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task SuccessfulExecutionIsRecorded()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using RuntimeTestContext context = new(
            key.PublicKeyPath,
            new FakePluginRuntime(new ScriptedJobHandler((_, _) => Task.FromResult(JobResult.Succeeded("done")))));
        await context.InitializeAsync(CancellationToken);
        await context.SeedActivePluginAsync("test-plugin", new Version(1, 0, 0), Definition(), CancellationToken);

        Guid executionId = await context.Dispatcher.DispatchAsync("test-job", CancellationToken);

        ExecutionRecord execution = await RequireExecutionAsync(context, executionId);
        Assert.Equal(JobExecutionStatus.Succeeded, execution.Status);
        Assert.Equal("done", execution.ResultSummary);
        Assert.NotNull(execution.StartedAt);
        Assert.NotNull(execution.EndedAt);
    }

    [Fact]
    public async Task TimeoutRecordsTimedOut()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using RuntimeTestContext context = new(
            key.PublicKeyPath,
            new FakePluginRuntime(new ScriptedJobHandler(async (_, token) =>
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, token);
                return JobResult.Succeeded();
            })));
        await context.InitializeAsync(CancellationToken);
        await context.SeedActivePluginAsync(
            "test-plugin",
            new Version(1, 0, 0),
            Definition(timeout: TimeSpan.FromMilliseconds(100)),
            CancellationToken);

        Guid executionId = await context.Dispatcher.DispatchAsync("test-job", CancellationToken);

        ExecutionRecord execution = await RequireExecutionAsync(context, executionId);
        Assert.Equal(JobExecutionStatus.TimedOut, execution.Status);
    }

    [Fact]
    public async Task CancellationRecordsCancelled()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using RuntimeTestContext context = new(
            key.PublicKeyPath,
            new FakePluginRuntime(new ScriptedJobHandler(async (_, token) =>
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, token);
                return JobResult.Succeeded();
            })));
        await context.InitializeAsync(CancellationToken);
        await context.SeedActivePluginAsync("test-plugin", new Version(1, 0, 0), Definition(), CancellationToken);

        Task<Guid> dispatch = context.Dispatcher.DispatchAsync("test-job", CancellationToken);
        IRunningExecution running = await WaitForRunningAsync(context);

        ExecutionRecord inFlight = await WaitForStatusAsync(context, running.ExecutionId, JobExecutionStatus.Running);
        Assert.NotNull(inFlight.StartedAt);

        Assert.True(await context.Dispatcher.CancelAsync(running.ExecutionId, "test cancel", CancellationToken));

        Guid executionId = await dispatch;
        ExecutionRecord execution = await RequireExecutionAsync(context, executionId);
        Assert.Equal(JobExecutionStatus.Cancelled, execution.Status);
        Assert.Equal("test cancel", execution.CancellationReason);
    }

    [Fact]
    public async Task RetryableFailureRetriesThenSucceeds()
    {
        int calls = 0;
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using RuntimeTestContext context = new(
            key.PublicKeyPath,
            new FakePluginRuntime(new ScriptedJobHandler((_, _) =>
            {
                if (Interlocked.Increment(ref calls) == 1)
                {
                    throw new InvalidOperationException("transient");
                }

                return Task.FromResult(JobResult.Succeeded("recovered"));
            })));
        await context.InitializeAsync(CancellationToken);
        await context.SeedActivePluginAsync(
            "test-plugin",
            new Version(1, 0, 0),
            Definition(retry: new RetryPolicy
            {
                MaxAttempts = 3,
                InitialDelay = TimeSpan.FromMilliseconds(10),
                BackoffMultiplier = 1.0,
                MaxDelay = TimeSpan.FromMilliseconds(50),
            }),
            CancellationToken);

        Guid executionId = await context.Dispatcher.DispatchAsync("test-job", CancellationToken);

        ExecutionRecord execution = await RequireExecutionAsync(context, executionId);
        Assert.Equal(JobExecutionStatus.Succeeded, execution.Status);
        Assert.Equal(2, execution.Attempt);
        Assert.Equal("recovered", execution.ResultSummary);
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task ReportedFailureStopsImmediately()
    {
        int calls = 0;
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using RuntimeTestContext context = new(
            key.PublicKeyPath,
            new FakePluginRuntime(new ScriptedJobHandler((_, _) =>
            {
                Interlocked.Increment(ref calls);
                return Task.FromResult(JobResult.Failed("permanent"));
            })));
        await context.InitializeAsync(CancellationToken);
        await context.SeedActivePluginAsync(
            "test-plugin",
            new Version(1, 0, 0),
            Definition(retry: new RetryPolicy { MaxAttempts = 3, InitialDelay = TimeSpan.FromMilliseconds(1) }),
            CancellationToken);

        Guid executionId = await context.Dispatcher.DispatchAsync("test-job", CancellationToken);

        ExecutionRecord execution = await RequireExecutionAsync(context, executionId);
        Assert.Equal(JobExecutionStatus.Failed, execution.Status);
        Assert.Equal(1, execution.Attempt);
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task NoOverlapPreventsConcurrentExecutionsOfSameJob()
    {
        int current = 0;
        int max = 0;
        object guard = new();
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using RuntimeTestContext context = new(
            key.PublicKeyPath,
            new FakePluginRuntime(new ScriptedJobHandler(async (_, token) =>
            {
                lock (guard)
                {
                    current++;
                    max = Math.Max(max, current);
                }

                await Task.Delay(150, token);

                lock (guard)
                {
                    current--;
                }

                return JobResult.Succeeded();
            })));
        await context.InitializeAsync(CancellationToken);
        await context.SeedActivePluginAsync(
            "test-plugin",
            new Version(1, 0, 0),
            Definition(policy: ConcurrencyPolicy.DisallowOverlap),
            CancellationToken);

        Task<Guid> first = context.Dispatcher.DispatchAsync("test-job", CancellationToken);
        Task<Guid> second = context.Dispatcher.DispatchAsync("test-job", CancellationToken);
        await Task.WhenAll(first, second);

        Assert.Equal(1, max);
    }

    [Fact]
    public async Task AllowParallelRunsSameJobConcurrently()
    {
        int current = 0;
        int max = 0;
        object guard = new();
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using RuntimeTestContext context = new(
            key.PublicKeyPath,
            new FakePluginRuntime(new ScriptedJobHandler(async (_, token) =>
            {
                lock (guard)
                {
                    current++;
                    max = Math.Max(max, current);
                }

                await Task.Delay(150, token);

                lock (guard)
                {
                    current--;
                }

                return JobResult.Succeeded();
            })));
        await context.InitializeAsync(CancellationToken);
        await context.SeedActivePluginAsync(
            "test-plugin",
            new Version(1, 0, 0),
            Definition(policy: ConcurrencyPolicy.AllowParallel),
            CancellationToken);

        Task<Guid> first = context.Dispatcher.DispatchAsync("test-job", CancellationToken);
        Task<Guid> second = context.Dispatcher.DispatchAsync("test-job", CancellationToken);
        await Task.WhenAll(first, second);

        Assert.Equal(2, max);
    }

    [Fact]
    public async Task FailureIsSanitized()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using RuntimeTestContext context = new(
            key.PublicKeyPath,
            new FakePluginRuntime(new ScriptedJobHandler((_, _) =>
                throw new InvalidOperationException("secret-token-abc123"))));
        await context.InitializeAsync(CancellationToken);
        await context.SeedActivePluginAsync(
            "test-plugin",
            new Version(1, 0, 0),
            Definition(retry: new RetryPolicy { MaxAttempts = 1 }),
            CancellationToken);

        Guid executionId = await context.Dispatcher.DispatchAsync("test-job", CancellationToken);

        ExecutionRecord execution = await RequireExecutionAsync(context, executionId);
        Assert.Equal(JobExecutionStatus.Failed, execution.Status);
        Assert.DoesNotContain("secret-token-abc123", execution.ResultSummary, StringComparison.Ordinal);
        Assert.Contains(nameof(InvalidOperationException), execution.ResultSummary, StringComparison.Ordinal);
    }

    [Fact]
    public async Task UnknownJobThrows()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using RuntimeTestContext context = new(
            key.PublicKeyPath,
            new FakePluginRuntime(new ScriptedJobHandler((_, _) => Task.FromResult(JobResult.Succeeded()))));
        await context.InitializeAsync(CancellationToken);

        await Assert.ThrowsAsync<KeyNotFoundException>(
            () => context.Dispatcher.DispatchAsync("missing-job", CancellationToken));

        ExecutionRejection rejection = await RequireSingleRejectionAsync(context);
        Assert.Equal("missing-job", rejection.JobId);
        Assert.Equal(ExecutionRejectionReason.NotFound, rejection.Reason);
        Assert.Null(rejection.PluginId);
        Assert.False(string.IsNullOrWhiteSpace(rejection.CorrelationId));
    }

    [Fact]
    public async Task DisabledJobDoesNotDispatch()
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

        DispatchRejectedException exception = await Assert.ThrowsAsync<DispatchRejectedException>(
            () => context.Dispatcher.DispatchAsync("test-job", CancellationToken));
        Assert.Equal(ExecutionRejectionReason.Disabled, exception.Reason);

        ExecutionRejection rejection = await RequireSingleRejectionAsync(context);
        Assert.Equal("test-job", rejection.JobId);
        Assert.Equal(ExecutionRejectionReason.Disabled, rejection.Reason);
    }

    [Fact]
    public async Task JobWithoutActiveVersionDoesNotDispatch()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using RuntimeTestContext context = new(
            key.PublicKeyPath,
            new FakePluginRuntime(new ScriptedJobHandler((_, _) => Task.FromResult(JobResult.Succeeded()))));
        await context.InitializeAsync(CancellationToken);
        await context.Jobs.UpdateAsync(Definition(), CancellationToken);

        DispatchRejectedException exception = await Assert.ThrowsAsync<DispatchRejectedException>(
            () => context.Dispatcher.DispatchAsync("test-job", CancellationToken));
        Assert.Equal(ExecutionRejectionReason.NoActiveVersion, exception.Reason);

        ExecutionRejection rejection = await RequireSingleRejectionAsync(context);
        Assert.Equal(ExecutionRejectionReason.NoActiveVersion, rejection.Reason);
    }

    [Fact]
    public async Task WorkerExecutionModeIsNotSupported()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using RuntimeTestContext context = new(
            key.PublicKeyPath,
            new FakePluginRuntime(new ScriptedJobHandler((_, _) => Task.FromResult(JobResult.Succeeded()))));
        await context.InitializeAsync(CancellationToken);
        await context.SeedActivePluginAsync(
            "test-plugin",
            new Version(1, 0, 0),
            Definition() with { ExecutionMode = ExecutionMode.Worker },
            CancellationToken);

        DispatchRejectedException exception = await Assert.ThrowsAsync<DispatchRejectedException>(
            () => context.Dispatcher.DispatchAsync("test-job", CancellationToken));
        Assert.Equal(ExecutionRejectionReason.ModeUnavailable, exception.Reason);

        ExecutionRejection rejection = await RequireSingleRejectionAsync(context);
        Assert.Equal(ExecutionRejectionReason.ModeUnavailable, rejection.Reason);
    }

    private static async Task<ExecutionRejection> RequireSingleRejectionAsync(RuntimeTestContext context)
    {
        await using IRegistryUnitOfWork unitOfWork = await context.UnitOfWorkFactory.BeginAsync(CancellationToken);
        IReadOnlyList<ExecutionRejection> rejections = await unitOfWork.Rejections.ListAsync(
            since: null,
            limit: 10,
            CancellationToken);
        return Assert.Single(rejections);
    }

    private static async Task<IRunningExecution> WaitForRunningAsync(RuntimeTestContext context)
    {
        for (int attempt = 0; attempt < 100; attempt++)
        {
            IReadOnlyList<IRunningExecution> running = context.RunningExecutions.ListForPlugin("test-plugin");
            if (running.Count > 0)
            {
                return running[0];
            }

            await Task.Delay(10, CancellationToken);
        }

        throw new InvalidOperationException("The execution did not start.");
    }

    private static async Task<ExecutionRecord> WaitForStatusAsync(
        RuntimeTestContext context,
        Guid executionId,
        JobExecutionStatus status)
    {
        for (int attempt = 0; attempt < 200; attempt++)
        {
            ExecutionRecord? execution = await context.ReadExecutionAsync(executionId, CancellationToken);
            if (execution is not null && execution.Status == status)
            {
                return execution;
            }

            await Task.Delay(10, CancellationToken);
        }

        throw new InvalidOperationException($"The execution never reached '{status}'.");
    }

    private static async Task<ExecutionRecord> RequireExecutionAsync(RuntimeTestContext context, Guid executionId)
    {
        ExecutionRecord? execution = await context.ReadExecutionAsync(executionId, CancellationToken);
        Assert.NotNull(execution);
        return execution;
    }

    private static JobDefinition Definition(
        string jobId = "test-job",
        ConcurrencyPolicy policy = ConcurrencyPolicy.DisallowOverlap,
        TimeSpan? timeout = null,
        RetryPolicy? retry = null,
        IReadOnlyDictionary<string, string?>? parameters = null) => new()
        {
            JobId = jobId,
            PluginId = "test-plugin",
            PluginVersion = new Version(1, 0, 0),
            Schedule = ScheduleSpec.FromCron("0 0 * * *"),
            ConcurrencyPolicy = policy,
            Timeout = timeout ?? TimeSpan.FromSeconds(30),
            RetryPolicy = retry ?? new RetryPolicy(),
            Parameters = parameters ?? new Dictionary<string, string?>(),
        };
}

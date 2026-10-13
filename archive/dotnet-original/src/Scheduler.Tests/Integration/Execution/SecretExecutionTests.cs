using Scheduler.Application.Observability;
using Scheduler.Application.Persistence;
using Scheduler.Application.Secrets;
using Scheduler.Contracts.Execution;
using Scheduler.Contracts.Jobs;
using Scheduler.Tests.Support;

namespace Scheduler.Tests.Integration.Execution;

public sealed class SecretExecutionTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task ResolvedValueIsUsedByTheHandlerButNeverPersisted()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        FakeSecretValueStore store = new();
        await store.SetAsync("api-token", "top-secret-value", Ct);

        string? observed = null;
        using RuntimeTestContext context = new(
            key.PublicKeyPath,
            new FakePluginRuntime(new ScriptedJobHandler(async (jobContext, token) =>
            {
                observed = await jobContext.Secrets.ResolveAsync("api-token", token);
                return JobResult.Succeeded("ok");
            })),
            secretValueStore: store);
        await context.InitializeAsync(Ct);
        await context.SeedActivePluginAsync("test-plugin", new Version(1, 0, 0), Definition(), Ct);
        await GrantAsync(context, "test-plugin", "test-job", "api-token");

        Guid executionId = await context.Dispatcher.DispatchAsync("test-job", Ct);

        Assert.Equal("top-secret-value", observed);

        ExecutionRecord? execution = await context.ReadExecutionAsync(executionId, Ct);
        Assert.NotNull(execution);
        Assert.Equal(JobExecutionStatus.Succeeded, execution.Status);
        Assert.DoesNotContain("top-secret-value", execution.ResultSummary ?? string.Empty, StringComparison.Ordinal);

        IReadOnlyList<AuditEntry> audit = await ReadAuditAsync(context);
        Assert.Contains(audit, entry => entry.Action == "secret.access.allowed" && entry.Target == "api-token");
        Assert.DoesNotContain(audit, entry => (entry.Details ?? string.Empty).Contains("top-secret-value", StringComparison.Ordinal));
    }

    [Fact]
    public async Task UngrantedResolutionFailsWithoutRetrying()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        FakeSecretValueStore store = new();
        int calls = 0;
        using RuntimeTestContext context = new(
            key.PublicKeyPath,
            new FakePluginRuntime(new ScriptedJobHandler(async (jobContext, token) =>
            {
                Interlocked.Increment(ref calls);
                await jobContext.Secrets.ResolveAsync("not-granted", token);
                return JobResult.Succeeded();
            })),
            secretValueStore: store);
        await context.InitializeAsync(Ct);
        await context.SeedActivePluginAsync(
            "test-plugin",
            new Version(1, 0, 0),
            Definition() with { RetryPolicy = new RetryPolicy { MaxAttempts = 3, InitialDelay = TimeSpan.FromMilliseconds(1) } },
            Ct);

        Guid executionId = await context.Dispatcher.DispatchAsync("test-job", Ct);

        ExecutionRecord? execution = await context.ReadExecutionAsync(executionId, Ct);
        Assert.NotNull(execution);
        Assert.Equal(JobExecutionStatus.Failed, execution.Status);
        Assert.Equal(1, execution.Attempt);
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task RetryKeepsTheValueTheExecutionAcquiredAtDispatch()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        FakeSecretValueStore store = new();
        await store.SetAsync("api-token", "value-v1", Ct);

        List<string> observed = [];
        int calls = 0;
        using RuntimeTestContext context = new(
            key.PublicKeyPath,
            new FakePluginRuntime(new ScriptedJobHandler(async (jobContext, token) =>
            {
                observed.Add(await jobContext.Secrets.ResolveAsync("api-token", token));
                if (Interlocked.Increment(ref calls) == 1)
                {
                    // Rotate the store between attempts; the running execution must not observe it.
                    await store.SetAsync("api-token", "value-v2", token);
                    throw new InvalidOperationException("transient");
                }

                return JobResult.Succeeded();
            })),
            secretValueStore: store);
        await context.InitializeAsync(Ct);
        await context.SeedActivePluginAsync(
            "test-plugin",
            new Version(1, 0, 0),
            Definition() with { RetryPolicy = new RetryPolicy { MaxAttempts = 3, InitialDelay = TimeSpan.FromMilliseconds(1) } },
            Ct);
        await GrantAsync(context, "test-plugin", "test-job", "api-token");

        Guid executionId = await context.Dispatcher.DispatchAsync("test-job", Ct);

        ExecutionRecord? execution = await context.ReadExecutionAsync(executionId, Ct);
        Assert.NotNull(execution);
        Assert.Equal(JobExecutionStatus.Succeeded, execution.Status);
        Assert.Equal(2, execution.Attempt);
        Assert.Equal(["value-v1", "value-v1"], observed);
        Assert.Equal("value-v2", await store.GetAsync("api-token", Ct));
    }

    private static async Task GrantAsync(RuntimeTestContext context, string pluginId, string jobId, string reference)
    {
        await using IRegistryUnitOfWork unitOfWork = await context.UnitOfWorkFactory.BeginAsync(Ct);
        await unitOfWork.SecretGrants.GrantAsync(
            new SecretGrant
            {
                PluginId = pluginId,
                JobId = jobId,
                SecretReference = reference,
                GrantedBy = "test",
                GrantedAt = DateTimeOffset.UtcNow,
            },
            Ct);
        await unitOfWork.CommitAsync(Ct);
    }

    private static async Task<IReadOnlyList<AuditEntry>> ReadAuditAsync(RuntimeTestContext context)
    {
        await using IRegistryUnitOfWork unitOfWork = await context.UnitOfWorkFactory.BeginAsync(Ct);
        return await unitOfWork.Audit.ListAsync(100, Ct);
    }

    private static JobDefinition Definition() => new()
    {
        JobId = "test-job",
        PluginId = "test-plugin",
        PluginVersion = new Version(1, 0, 0),
        Schedule = ScheduleSpec.FromCron("0 0 * * *"),
    };
}

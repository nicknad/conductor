using System.Globalization;
using Scheduler.Application.Execution;
using Scheduler.Application.Persistence;
using Scheduler.Application.PluginManagement;
using Scheduler.Application.Secrets;
using Scheduler.Contracts.Execution;
using Scheduler.Contracts.Jobs;
using Scheduler.Example.Plugin;
using Scheduler.Tests.Support;

namespace Scheduler.Tests.Integration.Execution;

/// <summary>
/// Runs the real, signed example plugin through the real in-process runtime and
/// dispatch path, proving the example's secret usage and the drain/cancel
/// contract without a divergent host.
/// </summary>
public sealed class ExamplePluginTests
{
    private const string SecretValue = "example-secret-value";

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task DispatchedExampleExecutionUsesTheGrantedSecretAndUnloadsCleanly()
    {
        using RuntimeTestContext context = await StartActiveAsync(holdMs: 0, new ExecutionOptions());

        Guid executionId = await context.Dispatcher.DispatchAsync(ReportingPlugin.ReportJobId, Ct);
        ExecutionRecord? execution = await context.ReadExecutionAsync(executionId, Ct);

        Assert.NotNull(execution);
        Assert.Equal(JobExecutionStatus.Succeeded, execution.Status);
        Assert.Contains(ReportDigest.OfValue(SecretValue), execution.ResultSummary ?? string.Empty, StringComparison.Ordinal);
        Assert.DoesNotContain(SecretValue, execution.ResultSummary ?? string.Empty, StringComparison.Ordinal);

        PluginOperation deactivation = await context.Manager.DeactivateAsync(ReportingPlugin.PluginId, Ct);

        Assert.Equal(PluginOperationStatus.Succeeded, deactivation.Status);
        Assert.False(context.Runtime.IsLoaded(ReportingPlugin.PluginId, ReportingPlugin.PluginVersion));
    }

    [Fact]
    public async Task WaitDrainLetsTheInFlightExampleExecutionComplete()
    {
        using RuntimeTestContext context = await StartActiveAsync(
            holdMs: 400,
            new ExecutionOptions { DrainPolicy = DrainPolicy.Wait, DrainTimeout = TimeSpan.FromSeconds(15) });

        Task<Guid> run = Task.Run(() => context.Dispatcher.DispatchAsync(ReportingPlugin.ReportJobId, Ct), Ct);
        await WaitForRunningAsync(context, Ct);

        PluginOperation deactivation = await context.Manager.DeactivateAsync(ReportingPlugin.PluginId, Ct);
        Guid executionId = await run;

        Assert.Equal(PluginOperationStatus.Succeeded, deactivation.Status);
        ExecutionRecord? execution = await context.ReadExecutionAsync(executionId, Ct);
        Assert.NotNull(execution);
        Assert.Equal(JobExecutionStatus.Succeeded, execution.Status);
    }

    [Fact]
    public async Task CancelCancelsTheInFlightExampleExecution()
    {
        using RuntimeTestContext context = await StartActiveAsync(
            holdMs: 30000,
            new ExecutionOptions { DrainPolicy = DrainPolicy.Cancel, DrainTimeout = TimeSpan.FromSeconds(15) });

        Task<Guid> run = Task.Run(() => context.Dispatcher.DispatchAsync(ReportingPlugin.ReportJobId, Ct), Ct);
        IRunningExecution running = await WaitForRunningAsync(context, Ct);

        Assert.True(await context.Dispatcher.CancelAsync(running.ExecutionId, "test cancel", Ct));
        Guid executionId = await run;

        ExecutionRecord? execution = await context.ReadExecutionAsync(executionId, Ct);
        Assert.NotNull(execution);
        Assert.Equal(JobExecutionStatus.Cancelled, execution.Status);
    }

    private static async Task<RuntimeTestContext> StartActiveAsync(int holdMs, ExecutionOptions options)
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        FakeSecretValueStore store = new();
        await store.SetAsync(ReportingPlugin.ApiKeyReference, SecretValue, Ct);

        RuntimeTestContext context = new(key.PublicKeyPath, executionOptions: options, secretValueStore: store);
        try
        {
            await context.InitializeAsync(Ct);
            await context.Manager.InstallAsync(new MemoryStream(ExamplePluginPackage.CreateSigned(key)), Ct);
            await context.Manager.ActivateAsync(ReportingPlugin.PluginId, ReportingPlugin.PluginVersion, Ct);
            await GrantAsync(context, ReportingPlugin.PluginId, ReportingPlugin.ReportJobId, ReportingPlugin.ApiKeyReference);

            JobDefinition definition = (await context.Jobs.GetAsync(ReportingPlugin.ReportJobId, Ct))!;
            await context.Jobs.UpdateAsync(
                definition with
                {
                    Parameters = new Dictionary<string, string?>
                    {
                        ["holdMs"] = holdMs.ToString(CultureInfo.InvariantCulture),
                    },
                },
                Ct);

            return context;
        }
        catch
        {
            context.Dispose();
            throw;
        }
    }

    private static async Task<IRunningExecution> WaitForRunningAsync(RuntimeTestContext context, CancellationToken cancellationToken)
    {
        for (int attempt = 0; attempt < 1000; attempt++)
        {
            IReadOnlyList<IRunningExecution> running = context.RunningExecutions.ListForPlugin(
                ReportingPlugin.PluginId,
                ReportingPlugin.PluginVersion);
            if (running.Count > 0)
            {
                return running[0];
            }

            await Task.Delay(10, cancellationToken);
        }

        throw new TimeoutException("No example execution became running.");
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
}

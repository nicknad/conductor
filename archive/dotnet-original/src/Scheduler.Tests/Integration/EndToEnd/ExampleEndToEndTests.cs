using System.IO.Abstractions;
using System.Net;
using System.Net.Http.Json;
using Scheduler.Application.Maintenance;
using Scheduler.Application.Observability;
using Scheduler.Application.Persistence;
using Scheduler.Application.PluginManagement;
using Scheduler.Cli;
using Scheduler.Contracts.Execution;
using Scheduler.Example.Plugin;
using Scheduler.Infrastructure.Persistence;
using Scheduler.Tests.Support;

namespace Scheduler.Tests.Integration.EndToEnd;

/// <summary>
/// The end-to-end acceptance path: package → install → validate → activate →
/// secret → run → observe → drain → backup, all through the real host and the
/// real management API. No test-only host is involved.
/// </summary>
public sealed class ExampleEndToEndTests
{
    private const string SecretValue = "example-api-key-value";

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task FullFlowUsesTheGrantedSecretAndPreservesStateThroughBackupAndDrain()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        await using ExampleHost host = await ExampleHost.StartAsync(key, Ct);
        ISchedulerApiClient client = host.Client;

        PluginOperation install = await client.InstallPluginAsync(host.PackagePath, Ct);
        Assert.Equal(PluginOperationStatus.Succeeded, install.Status);

        ValidationReport validation = await client.ValidatePluginAsync(ReportingPlugin.PluginId, ReportingPlugin.PluginVersion, Ct);
        Assert.True(validation.IsValid, string.Join("; ", validation.Errors));

        PluginOperation activation = await client.ActivatePluginAsync(ReportingPlugin.PluginId, ReportingPlugin.PluginVersion, Ct);
        Assert.Equal(PluginOperationStatus.Succeeded, activation.Status);

        IReadOnlyList<Scheduler.Contracts.Jobs.JobDefinition> jobs = await client.ListJobsAsync(Ct);
        Assert.Contains(jobs, job => job.JobId == ReportingPlugin.ReportJobId);

        await client.SetSecretAsync(ReportingPlugin.ApiKeyReference, SecretValue, Ct);
        await client.GrantSecretAsync(ReportingPlugin.PluginId, ReportingPlugin.ReportJobId, ReportingPlugin.ApiKeyReference, Ct);

        Guid executionId = await client.RunJobAsync(ReportingPlugin.ReportJobId, Ct);

        ExecutionRecord? execution = await client.GetExecutionAsync(executionId, Ct);
        Assert.NotNull(execution);
        Assert.Equal(JobExecutionStatus.Succeeded, execution.Status);
        string expectedDigest = ReportDigest.OfValue(SecretValue);
        Assert.Contains(expectedDigest, execution.ResultSummary ?? string.Empty, StringComparison.Ordinal);
        Assert.DoesNotContain(SecretValue, execution.ResultSummary ?? string.Empty, StringComparison.Ordinal);

        IReadOnlyList<ExecutionLogEntry> logs = await client.GetExecutionLogsAsync(executionId, Ct);
        Assert.Contains(logs, entry => entry.Message.Contains("report key resolved", StringComparison.Ordinal));
        Assert.DoesNotContain(logs, entry => entry.Message.Contains(SecretValue, StringComparison.Ordinal));
        Assert.DoesNotContain(logs, entry => (entry.Exception ?? string.Empty).Contains(SecretValue, StringComparison.Ordinal));

        string reportPath = Path.Combine(Path.GetTempPath(), "scheduler-example-reports", executionId.ToString("N") + ".txt");
        try
        {
            Assert.True(File.Exists(reportPath), $"Expected the example report at '{reportPath}'.");
            string report = await File.ReadAllTextAsync(reportPath, Ct);
            Assert.Contains($"key-digest={expectedDigest}", report, StringComparison.Ordinal);
            Assert.DoesNotContain(SecretValue, report, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(reportPath);
        }

        IReadOnlyList<AuditEntry> audit = await client.ListAuditAsync(new AuditFilter { Limit = 200 }, Ct);
        Assert.Contains(audit, entry => entry.Action == "plugin.install");
        Assert.Contains(audit, entry => entry.Action == "plugin.activate");
        Assert.Contains(audit, entry => entry.Action == "job.run");
        Assert.Contains(audit, entry => entry.Action == "secret.access.allowed" && entry.Target == ReportingPlugin.ApiKeyReference);
        Assert.DoesNotContain(audit, entry => (entry.Details ?? string.Empty).Contains(SecretValue, StringComparison.Ordinal));

        ExecutionSummary summary = await client.GetSummaryAsync(window: null, Ct);
        Assert.True(summary.Executions.Succeeded >= 1, "The summary must reflect the succeeded execution.");

        string backupDestination = Path.Combine(host.BackupRoot, "snapshot");
        BackupResult backup = await client.BackupAsync(backupDestination, Ct);
        Assert.True(backup.Verified);

        (PluginActivationRecord? backupActivation, PluginVersionRecord? backupVersion) =
            await ReadBackupAsync(Path.Combine(backupDestination, "registry.db"), Ct);
        Assert.NotNull(backupActivation);
        Assert.Equal(ReportingPlugin.PluginVersion, backupActivation.Version);
        Assert.NotNull(backupVersion);
        Assert.Equal(PluginLifecycleState.Active, backupVersion.State);

        PluginOperation deactivation = await client.DeactivatePluginAsync(ReportingPlugin.PluginId, Ct);
        Assert.Equal(PluginOperationStatus.Succeeded, deactivation.Status);

        IReadOnlyList<PluginDescriptor> plugins = await client.ListPluginsAsync(Ct);
        PluginDescriptor descriptor = Assert.Single(plugins);
        Assert.Equal(ReportingPlugin.PluginId, descriptor.PluginId);
        Assert.Null(descriptor.ActiveVersion);
        Assert.Equal(PluginLifecycleState.Retired, descriptor.State);
    }

    [Fact]
    public async Task TamperedPackageIsRejectedAndActiveVersionIsUntouched()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        await using ExampleHost host = await ExampleHost.StartAsync(key, Ct);
        ISchedulerApiClient client = host.Client;

        Assert.Equal(PluginOperationStatus.Succeeded, (await client.InstallPluginAsync(host.PackagePath, Ct)).Status);
        Assert.Equal(
            PluginOperationStatus.Succeeded,
            (await client.ActivatePluginAsync(ReportingPlugin.PluginId, ReportingPlugin.PluginVersion, Ct)).Status);

        Version tamperedVersion = new(9, 9, 9);
        string tamperedPath = Path.Combine(host.Root, "tampered-package.zip");
        await File.WriteAllBytesAsync(tamperedPath, ExamplePluginPackage.CreateTampered(key, tamperedVersion), Ct);

        SchedulerApiException rejected = await Assert.ThrowsAsync<SchedulerApiException>(
            () => client.InstallPluginAsync(tamperedPath, Ct));
        Assert.Equal((int)HttpStatusCode.UnprocessableEntity, rejected.StatusCode);

        IReadOnlyList<PluginDescriptor> plugins = await client.ListPluginsAsync(Ct);
        PluginDescriptor descriptor = Assert.Single(plugins);
        Assert.Equal(ReportingPlugin.PluginVersion, descriptor.ActiveVersion);
        Assert.Equal(PluginLifecycleState.Active, descriptor.State);
    }

    [Fact]
    public async Task UnauthenticatedAndUnderPermissionedRequestsAreRejected()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        await using ExampleHost host = await ExampleHost.StartAsync(key, Ct);

        using HttpClient anonymous = host.CreateHttpClient(token: null);
        using HttpResponseMessage unauthenticated = await anonymous.GetAsync("api/plugins", Ct);
        Assert.Equal(HttpStatusCode.Unauthorized, unauthenticated.StatusCode);

        using HttpClient admin = host.CreateHttpClient(ExampleHost.AdminToken);
        using HttpResponseMessage read = await admin.GetAsync("api/plugins", Ct);
        Assert.Equal(HttpStatusCode.OK, read.StatusCode);

        using HttpResponseMessage forbidden = await admin.PostAsync(
            $"api/plugins/{ReportingPlugin.PluginId}/remove",
            content: null,
            Ct);
        Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);

        string hostLog = host.ReadHostLog();
        Assert.Contains("request rejected", hostLog, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("request forbidden", hostLog, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ReplayingAnActivationOperationReturnsTheSameResult()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        await using ExampleHost host = await ExampleHost.StartAsync(key, Ct);
        ISchedulerApiClient client = host.Client;

        Assert.Equal(PluginOperationStatus.Succeeded, (await client.InstallPluginAsync(host.PackagePath, Ct)).Status);

        Guid operationId = Guid.NewGuid();
        using HttpClient http = host.CreateHttpClient(ExampleHost.AdminToken);

        PluginOperation first = await ActivateWithOperationIdAsync(http, operationId, Ct);
        PluginOperation replay = await ActivateWithOperationIdAsync(http, operationId, Ct);

        Assert.Equal(PluginOperationStatus.Succeeded, first.Status);
        Assert.Equal(first.OperationId, replay.OperationId);
        Assert.Equal(first.Status, replay.Status);
    }

    private static async Task<PluginOperation> ActivateWithOperationIdAsync(
        HttpClient http,
        Guid operationId,
        CancellationToken cancellationToken)
    {
        using HttpRequestMessage request = new(
            HttpMethod.Post,
            $"api/plugins/{ReportingPlugin.PluginId}/{ReportingPlugin.PluginVersion}/activate");
        request.Headers.Add("X-Operation-Id", operationId.ToString("D"));

        using HttpResponseMessage response = await http.SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<PluginOperation>(cancellationToken)
            ?? throw new InvalidOperationException("The management API returned an empty activation body.");
    }

    private static async Task<(PluginActivationRecord? Activation, PluginVersionRecord? Version)> ReadBackupAsync(
        string databasePath,
        CancellationToken cancellationToken)
    {
        SqliteConnectionFactory factory = new(new PersistenceOptions { DatabasePath = databasePath }, new FileSystem());
        SqliteRegistryUnitOfWorkFactory unitOfWorkFactory = new(factory);
        await using IRegistryUnitOfWork unitOfWork = await unitOfWorkFactory.BeginAsync(cancellationToken);
        PluginActivationRecord? activation = await unitOfWork.Plugins.GetActivationAsync(ReportingPlugin.PluginId, cancellationToken);
        PluginVersionRecord? version = await unitOfWork.Plugins.GetVersionAsync(
            ReportingPlugin.PluginId,
            ReportingPlugin.PluginVersion,
            cancellationToken);
        return (activation, version);
    }
}

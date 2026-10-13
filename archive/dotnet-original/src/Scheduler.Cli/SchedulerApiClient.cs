using Scheduler.Application.Maintenance;
using Scheduler.Application.Observability;
using Scheduler.Application.Persistence;
using Scheduler.Application.PluginManagement;
using Scheduler.Contracts.Jobs;

namespace Scheduler.Cli;

/// <summary>
/// The management-API surface the CLI needs. The CLI never re-implements logic;
/// it only formats what the host returns.
/// </summary>
public interface ISchedulerApiClient
{
    Task<ExecutionSummary> GetSummaryAsync(TimeSpan? window, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<JobDefinition>> ListJobsAsync(CancellationToken cancellationToken = default);

    Task<Guid> RunJobAsync(string jobId, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<ExecutionRecord>> ListExecutionsAsync(ExecutionFilter filter, CancellationToken cancellationToken = default);

    Task<ExecutionRecord?> GetExecutionAsync(Guid executionId, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<ExecutionLogEntry>> GetExecutionLogsAsync(Guid executionId, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<AuditEntry>> ListAuditAsync(AuditFilter filter, CancellationToken cancellationToken = default);

    Task<HealthReport> GetHealthAsync(CancellationToken cancellationToken = default);

    Task<IReadOnlyList<PluginDescriptor>> ListPluginsAsync(CancellationToken cancellationToken = default);

    Task<PluginOperation> InstallPluginAsync(string packagePath, CancellationToken cancellationToken = default);

    Task<ValidationReport> ValidatePluginAsync(string pluginId, Version version, CancellationToken cancellationToken = default);

    Task<PluginOperation> ActivatePluginAsync(string pluginId, Version version, CancellationToken cancellationToken = default);

    Task<PluginOperation> DeactivatePluginAsync(string pluginId, CancellationToken cancellationToken = default);

    Task<PluginOperation> RollbackPluginAsync(string pluginId, Version version, CancellationToken cancellationToken = default);

    Task<PluginOperation> RemovePluginAsync(string pluginId, CancellationToken cancellationToken = default);

    Task SetSecretAsync(string secretReference, string value, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<string>> ListSecretReferencesAsync(CancellationToken cancellationToken = default);

    Task RemoveSecretAsync(string secretReference, CancellationToken cancellationToken = default);

    Task GrantSecretAsync(string pluginId, string? jobId, string secretReference, CancellationToken cancellationToken = default);

    Task<bool> RevokeSecretAsync(string pluginId, string? jobId, string secretReference, CancellationToken cancellationToken = default);

    Task<BackupResult> BackupAsync(string destination, CancellationToken cancellationToken = default);
}

/// <summary>A non-success response from the management API, carrying the reason when present.</summary>
public sealed class SchedulerApiException : Exception
{
    public SchedulerApiException(int statusCode, string message, string? reason = null)
        : base(message)
    {
        StatusCode = statusCode;
        Reason = reason;
    }

    public int StatusCode { get; }

    public string? Reason { get; }
}

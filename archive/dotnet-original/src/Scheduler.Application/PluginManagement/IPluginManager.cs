namespace Scheduler.Application.PluginManagement;

/// <summary>
/// Authoritative lifecycle use-case surface for plugin versions. All lifecycle
/// transitions (install, validate, activate, deactivate, rollback, remove) go
/// through this interface; neither the filesystem nor plugins can self-activate.
/// </summary>
public interface IPluginManager
{
    /// <summary>
    /// Stages an uploaded package and runs validation + promotion. Does not
    /// affect any active version. The stream is read once and not retained.
    /// </summary>
    Task<PluginOperation> InstallAsync(Stream package, CancellationToken cancellationToken = default);

    /// <summary>(Re-)validates a staged version and persists the validation result.</summary>
    Task<ValidationReport> ValidateAsync(string pluginId, Version version, CancellationToken cancellationToken = default);

    /// <summary>Activates a validated version. Long-running; returns an operation to track.</summary>
    Task<PluginOperation> ActivateAsync(string pluginId, Version version, CancellationToken cancellationToken = default);

    /// <summary>Stops dispatching new executions for the plugin and applies the drain policy.</summary>
    Task<PluginOperation> DeactivateAsync(string pluginId, CancellationToken cancellationToken = default);

    /// <summary>Restores a previously validated version without restarting the host.</summary>
    Task<PluginOperation> RollbackAsync(string pluginId, Version targetVersion, CancellationToken cancellationToken = default);

    /// <summary>Disables scheduling, drains, unregisters, and retains artifacts for the audit period.</summary>
    Task<PluginOperation> RemoveAsync(string pluginId, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<PluginDescriptor>> ListAsync(CancellationToken cancellationToken = default);

    Task<IReadOnlyList<PluginVersionDescriptor>> ListVersionsAsync(string pluginId, CancellationToken cancellationToken = default);
}

public sealed record PluginDescriptor(string PluginId, Version? ActiveVersion, PluginLifecycleState State);

public sealed record PluginVersionDescriptor(
    string PluginId,
    Version Version,
    PluginLifecycleState State,
    DateTimeOffset? InstalledAt,
    DateTimeOffset? ValidatedAt);

/// <summary>Handle for a lifecycle operation. Durable and resumable after a crash.</summary>
public sealed record PluginOperation(
    Guid OperationId,
    string PluginId,
    Version? Version,
    PluginOperationStatus Status,
    string? Error = null);

public enum PluginOperationStatus
{
    Pending,
    Running,
    Succeeded,
    Failed,

    /// <summary>An incomplete operation detected during startup reconciliation.</summary>
    Recovering,
}

/// <summary>Result of validating a staged plugin version.</summary>
public sealed record ValidationReport(
    string PluginId,
    Version Version,
    bool IsValid,
    IReadOnlyList<string> Errors,
    IReadOnlyList<string> Warnings)
{
    public static ValidationReport Valid(string pluginId, Version version, IReadOnlyList<string> warnings) =>
        new(pluginId, version, IsValid: true, Errors: [], Warnings: warnings);

    public static ValidationReport Invalid(string pluginId, Version version, IReadOnlyList<string> errors) =>
        new(pluginId, version, IsValid: false, Errors: errors, Warnings: []);
}

/// <summary>
/// Lifecycle of a plugin version. Independent from the enabled state of any
/// job definition: an active plugin may have disabled schedules.
/// </summary>
public enum PluginLifecycleState
{
    Uploaded,
    Validating,
    Rejected,
    Staged,
    Activating,
    Active,
    Draining,
    Retired,
    Removed,
    Failed,
}

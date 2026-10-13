using Scheduler.Application.PluginManagement;
using Scheduler.Contracts.Execution;

namespace Scheduler.Application.Persistence;

/// <summary>
/// Durable projection of one plugin version row. State transitions belong to the
/// plugin manager; this type carries only the persisted shape.
/// </summary>
public sealed record PluginVersionRecord
{
    public required string PluginId { get; init; }

    public required Version Version { get; init; }

    public required string ContractVersion { get; init; }

    public required string EntryAssembly { get; init; }

    public required string EntryType { get; init; }

    public required ExecutionMode ExecutionMode { get; init; }

    public required string ArtifactHash { get; init; }

    public required PluginLifecycleState State { get; init; }

    public required DateTimeOffset InstalledAt { get; init; }

    public DateTimeOffset? ValidatedAt { get; init; }

    public string? ValidationError { get; init; }

    /// <summary>Canonical manifest JSON as parsed and validated at install time.</summary>
    public string? ManifestJson { get; init; }

    /// <summary>Staging directory while an install is in progress; cleared on promotion.</summary>
    public string? StagingPath { get; init; }

    /// <summary>Immutable artifact path once the verified package is promoted.</summary>
    public string? ArtifactPath { get; init; }

    /// <summary>
    /// Reason the version's assembly context could not be unloaded. A non-null
    /// value marks an unclean unload: the version is retained but its context is
    /// still alive and must never be treated as removed.
    /// </summary>
    public string? UncleanUnloadReason { get; init; }
}

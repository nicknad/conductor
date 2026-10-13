namespace Scheduler.Application.Packaging;

/// <summary>
/// Content-addressed, immutable store of promoted plugin artifacts. Handles the
/// staging → promotion boundary so nothing unverified is ever visible as a
/// retained artifact.
/// </summary>
public interface IArtifactStore
{
    /// <summary>Creates an isolated staging directory for one install operation.</summary>
    Task<string> CreateStagingDirectoryAsync(Guid operationId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Promotes a validated staging directory into immutable artifact storage.
    /// Promotion is idempotent: identical content already present is accepted;
    /// differing content at the same identity is rejected.
    /// </summary>
    Task<StagedArtifact> PromoteAsync(
        string pluginId,
        Version version,
        string stagingRoot,
        string artifactHash,
        CancellationToken cancellationToken = default);

    /// <summary>Removes a staging directory after a failed or completed operation.</summary>
    Task DiscardStagingAsync(string stagingRoot, CancellationToken cancellationToken = default);

    /// <summary>Removes all staging residue; run at startup to sweep crashed installs.</summary>
    Task ClearStagingAsync(CancellationToken cancellationToken = default);

    Task<bool> ExistsAsync(string pluginId, Version version, CancellationToken cancellationToken = default);

    /// <summary>Opens a retained artifact for re-validation, or returns null when absent.</summary>
    Task<ExtractedPackage?> OpenAsync(string pluginId, Version version, CancellationToken cancellationToken = default);
}

/// <summary>A promoted, immutable artifact.</summary>
public sealed record StagedArtifact(string PluginId, Version Version, string ArtifactPath, string ArtifactHash);

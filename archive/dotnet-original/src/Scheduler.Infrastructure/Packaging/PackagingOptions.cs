using Scheduler.Application.Packaging;

namespace Scheduler.Infrastructure.Packaging;

/// <summary>
/// Explicit, configuration-driven packaging locations and limits. Relative
/// paths resolve against <see cref="BaseDirectory" /> (the host content root),
/// never the process working directory.
/// </summary>
public sealed class PackagingOptions
{
    public required string ArtifactsRoot { get; init; }

    public required string StagingRoot { get; init; }

    /// <summary>PEM public key used to verify package signatures.</summary>
    public required string PublicKeyPath { get; init; }

    public string? BaseDirectory { get; init; }

    public string? DataRoot { get; init; }

    public string? LogsRoot { get; init; }

    /// <summary>Root backups may be written to; the destination is confined to it.</summary>
    public string BackupRoot { get; init; } = "data/backups";

    public int MaxEntryCount { get; init; } = PackagingLimits.Default.MaxEntryCount;

    public long MaxEntryUncompressedBytes { get; init; } = PackagingLimits.Default.MaxEntryUncompressedBytes;

    public long MaxTotalUncompressedBytes { get; init; } = PackagingLimits.Default.MaxTotalUncompressedBytes;

    public double MaxCompressionRatio { get; init; } = PackagingLimits.Default.MaxCompressionRatio;

    public PackagingLimits ToLimits() => new(
        MaxEntryCount,
        MaxEntryUncompressedBytes,
        MaxTotalUncompressedBytes,
        MaxCompressionRatio);

    /// <summary>Roots the host may write to; the signing key must live outside all of them.</summary>
    public IReadOnlyList<string> WritableRoots =>
        new[] { DataRoot, ArtifactsRoot, StagingRoot, LogsRoot, BackupRoot }
            .Where(root => !string.IsNullOrWhiteSpace(root))
            .Select(root => root!)
            .ToArray();
}

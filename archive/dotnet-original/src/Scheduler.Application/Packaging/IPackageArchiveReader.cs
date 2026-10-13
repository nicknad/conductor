namespace Scheduler.Application.Packaging;

/// <summary>
/// Extracts a package archive into a staging root with all safety gates
/// enforced (no traversal, symlinks, duplicates, or size/ratio overruns).
/// </summary>
public interface IPackageArchiveReader
{
    /// <exception cref="PackageValidationException">The archive is unsafe or malformed.</exception>
    Task<ExtractedPackage> ExtractAsync(
        Stream archive,
        string stagingRoot,
        PackagingLimits limits,
        CancellationToken cancellationToken = default);
}

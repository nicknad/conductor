namespace Scheduler.Application.Packaging;

/// <summary>
/// Bounds enforced while extracting a package. They cap resource use and reject
/// decompression bombs before anything is promoted.
/// </summary>
public sealed record PackagingLimits(
    int MaxEntryCount,
    long MaxEntryUncompressedBytes,
    long MaxTotalUncompressedBytes,
    double MaxCompressionRatio)
{
    public static PackagingLimits Default { get; } = new(
        MaxEntryCount: 4096,
        MaxEntryUncompressedBytes: 256L * 1024 * 1024,
        MaxTotalUncompressedBytes: 1024L * 1024 * 1024,
        MaxCompressionRatio: 200.0);
}

namespace Scheduler.Application.Packaging;

/// <summary>
/// The result of safely extracting a package archive into a staging root:
/// the entry list (with content hashes) plus the raw manifest and signature
/// bytes, so validating code never needs direct filesystem access.
/// </summary>
public sealed record ExtractedPackage(
    string ExtractionRoot,
    IReadOnlyList<PackageEntry> Entries,
    byte[]? ManifestBytes,
    byte[]? SignatureBytes);

namespace Scheduler.Application.Packaging;

/// <summary>
/// One regular file inside a package. <see cref="Path" /> is the archive-relative
/// path using forward slashes; <see cref="ContentHash" /> is the lowercase hex
/// SHA-256 of the entry's bytes.
/// </summary>
public sealed record PackageEntry(string Path, long Length, string ContentHash);

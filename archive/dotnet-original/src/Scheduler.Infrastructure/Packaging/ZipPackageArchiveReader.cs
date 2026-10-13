using System.Buffers;
using System.IO.Abstractions;
using System.IO.Compression;
using System.Security.Cryptography;
using Scheduler.Application.Packaging;

namespace Scheduler.Infrastructure.Packaging;

/// <summary>
/// Extracts a ZIP package into a staging root while enforcing archive safety:
/// no path traversal or absolute/drive-letter paths, no symlinks or special
/// entries, no duplicate entries, and bounded entry count and uncompressed size
/// (guarding against decompression bombs). Nothing is promoted here.
/// </summary>
public sealed class ZipPackageArchiveReader : IPackageArchiveReader
{
    private const int BufferSize = 81920;

    private readonly IFileSystem _fileSystem;

    public ZipPackageArchiveReader(IFileSystem fileSystem)
    {
        ArgumentNullException.ThrowIfNull(fileSystem);
        _fileSystem = fileSystem;
    }

    public async Task<ExtractedPackage> ExtractAsync(
        Stream archive,
        string stagingRoot,
        PackagingLimits limits,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(archive);
        ArgumentException.ThrowIfNullOrWhiteSpace(stagingRoot);
        ArgumentNullException.ThrowIfNull(limits);

        string root = _fileSystem.Path.GetFullPath(stagingRoot);
        _fileSystem.Directory.CreateDirectory(root);

        List<string> errors = [];
        List<PackageEntry> entries = [];
        HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);
        byte[]? manifestBytes = null;
        byte[]? signatureBytes = null;
        long totalBytes = 0;

        using ZipArchive zip = new(archive, ZipArchiveMode.Read, leaveOpen: true);
        foreach (ZipArchiveEntry entry in zip.Entries)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (IsDirectoryEntry(entry))
            {
                continue;
            }

            if (entries.Count >= limits.MaxEntryCount)
            {
                errors.Add($"Package exceeds the maximum of {limits.MaxEntryCount} entries.");
                break;
            }

            string? normalized = TryNormalizePath(entry.FullName, out string? pathError);
            if (normalized is null)
            {
                errors.Add(pathError!);
                continue;
            }

            if (!seen.Add(normalized))
            {
                errors.Add($"Package contains a duplicate entry '{normalized}'.");
                continue;
            }

            if (IsSpecialEntry(entry))
            {
                errors.Add($"Entry '{normalized}' is not a regular file.");
                continue;
            }

            if (entry.Length > limits.MaxEntryUncompressedBytes)
            {
                errors.Add($"Entry '{normalized}' exceeds the maximum uncompressed size.");
                continue;
            }

            if (ExceedsCompressionRatio(entry, limits.MaxCompressionRatio))
            {
                errors.Add($"Entry '{normalized}' exceeds the maximum compression ratio.");
                continue;
            }

            string destination = _fileSystem.Path.Combine(
                root,
                normalized.Replace('/', _fileSystem.Path.DirectorySeparatorChar));
            if (!PackagingPaths.IsWithin(destination, root, _fileSystem))
            {
                errors.Add($"Entry '{normalized}' escapes the staging root.");
                continue;
            }

            string? directory = _fileSystem.Path.GetDirectoryName(destination);
            if (!string.IsNullOrEmpty(directory))
            {
                _fileSystem.Directory.CreateDirectory(directory);
            }

            (long Length, string Hash) written = await WriteAndHashAsync(
                entry,
                destination,
                limits.MaxEntryUncompressedBytes,
                cancellationToken);
            entries.Add(new PackageEntry(normalized, written.Length, written.Hash));

            // Total is measured from actual streamed bytes, never the untrusted
            // central-directory length, so a lying archive cannot evade the cap.
            totalBytes += written.Length;
            if (totalBytes > limits.MaxTotalUncompressedBytes)
            {
                errors.Add("Package exceeds the maximum total uncompressed size.");
                break;
            }

            if (string.Equals(normalized, PackageLayout.ManifestFileName, StringComparison.Ordinal))
            {
                manifestBytes = _fileSystem.File.ReadAllBytes(destination);
            }
            else if (string.Equals(normalized, PackageLayout.SignatureFileName, StringComparison.Ordinal))
            {
                signatureBytes = _fileSystem.File.ReadAllBytes(destination);
            }
        }

        if (errors.Count > 0)
        {
            throw new PackageValidationException(errors);
        }

        if (entries.Count == 0)
        {
            throw new PackageValidationException("Package archive contains no files.");
        }

        return new ExtractedPackage(root, entries, manifestBytes, signatureBytes);
    }

    private async Task<(long Length, string Hash)> WriteAndHashAsync(
        ZipArchiveEntry entry,
        string destination,
        long maxBytes,
        CancellationToken cancellationToken)
    {
        await using Stream source = entry.Open();
        await using Stream target = _fileSystem.File.Create(destination);
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        byte[] buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
        try
        {
            long total = 0;
            int read;
            while ((read = await source.ReadAsync(buffer, cancellationToken)) > 0)
            {
                total += read;
                if (total > maxBytes)
                {
                    throw new PackageValidationException(
                        $"Entry '{entry.FullName}' exceeds the maximum uncompressed size.");
                }

                hash.AppendData(buffer, 0, read);
                await target.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
            }

            return (total, Convert.ToHexStringLower(hash.GetHashAndReset()));
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static bool IsDirectoryEntry(ZipArchiveEntry entry) =>
        entry.Name.Length == 0
        || entry.FullName.EndsWith('/')
        || entry.FullName.EndsWith('\\');

    private static bool IsSpecialEntry(ZipArchiveEntry entry)
    {
        int unixMode = (entry.ExternalAttributes >> 16) & 0xFFFF;
        int type = unixMode & 0xF000;
        return type is 0xA000 or 0x1000 or 0x2000 or 0x6000 or 0xC000;
    }

    private static bool ExceedsCompressionRatio(ZipArchiveEntry entry, double maxRatio)
    {
        if (entry.Length <= 0 || entry.CompressedLength <= 0)
        {
            return false;
        }

        return (double)entry.Length / entry.CompressedLength > maxRatio;
    }

    private static string? TryNormalizePath(string fullName, out string? error)
    {
        error = null;
        if (string.IsNullOrEmpty(fullName))
        {
            error = "Package contains an entry with an empty name.";
            return null;
        }

        string path = fullName.Replace('\\', '/');
        if (path.StartsWith('/'))
        {
            error = $"Entry '{fullName}' uses an absolute path.";
            return null;
        }

        if (path.Length >= 2 && char.IsLetter(path[0]) && path[1] == ':')
        {
            error = $"Entry '{fullName}' uses a drive-letter path.";
            return null;
        }

        string[] segments = path.Split('/');
        foreach (string segment in segments)
        {
            if (segment.Length == 0 || segment == "." || segment == "..")
            {
                error = $"Entry '{fullName}' contains an unsafe path segment.";
                return null;
            }
        }

        return string.Join('/', segments);
    }
}

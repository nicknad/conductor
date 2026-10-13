using System.IO.Abstractions;
using System.Security.Cryptography;
using Scheduler.Application.Packaging;

namespace Scheduler.Infrastructure.Packaging;

/// <summary>
/// Content-addressed, immutable artifact store on the local filesystem. Layout
/// is <c>{ArtifactsRoot}/{pluginId}/{version}/…</c>; promotion moves a verified
/// staging directory into place atomically (rename, with a copy fallback) and
/// never mutates an existing artifact.
/// </summary>
public sealed class FileSystemArtifactStore : IArtifactStore
{
    private readonly IFileSystem _fileSystem;
    private readonly string _artifactsRoot;
    private readonly string _stagingRoot;

    public FileSystemArtifactStore(PackagingOptions options, IFileSystem fileSystem)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(fileSystem);

        _fileSystem = fileSystem;
        _artifactsRoot = PackagingPaths.Resolve(options.ArtifactsRoot, options.BaseDirectory, fileSystem);
        _stagingRoot = PackagingPaths.Resolve(options.StagingRoot, options.BaseDirectory, fileSystem);
    }

    public Task<string> CreateStagingDirectoryAsync(Guid operationId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        string path = _fileSystem.Path.Combine(_stagingRoot, operationId.ToString("N"));
        if (_fileSystem.Directory.Exists(path))
        {
            _fileSystem.Directory.Delete(path, recursive: true);
        }

        _fileSystem.Directory.CreateDirectory(path);
        return Task.FromResult(path);
    }

    public Task<StagedArtifact> PromoteAsync(
        string pluginId,
        Version version,
        string stagingRoot,
        string artifactHash,
        CancellationToken cancellationToken = default)
    {
        ValidatePluginId(pluginId);
        ArgumentNullException.ThrowIfNull(version);
        ArgumentException.ThrowIfNullOrWhiteSpace(stagingRoot);
        ArgumentException.ThrowIfNullOrWhiteSpace(artifactHash);
        cancellationToken.ThrowIfCancellationRequested();

        string destination = GetArtifactPath(pluginId, version);
        if (_fileSystem.Directory.Exists(destination))
        {
            string existingHash = ComputeArtifactHash(destination);
            if (!string.Equals(existingHash, artifactHash, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"Artifact '{pluginId}' '{version}' already exists with different content.");
            }

            _ = DiscardStagingAsync(stagingRoot, cancellationToken);
            return Task.FromResult(new StagedArtifact(pluginId, version, destination, artifactHash));
        }

        string? parent = _fileSystem.Path.GetDirectoryName(destination);
        if (!string.IsNullOrEmpty(parent))
        {
            _fileSystem.Directory.CreateDirectory(parent);
        }

        try
        {
            _fileSystem.Directory.Move(stagingRoot, destination);
        }
        catch (IOException)
        {
            CopyDirectory(stagingRoot, destination);
            _fileSystem.Directory.Delete(stagingRoot, recursive: true);
        }

        return Task.FromResult(new StagedArtifact(pluginId, version, destination, artifactHash));
    }

    public Task DiscardStagingAsync(string stagingRoot, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(stagingRoot) || !_fileSystem.Directory.Exists(stagingRoot))
        {
            return Task.CompletedTask;
        }

        try
        {
            _fileSystem.Directory.Delete(stagingRoot, recursive: true);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }

        return Task.CompletedTask;
    }

    public Task ClearStagingAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!_fileSystem.Directory.Exists(_stagingRoot))
        {
            return Task.CompletedTask;
        }

        foreach (string directory in _fileSystem.Directory.EnumerateDirectories(_stagingRoot))
        {
            _ = DiscardStagingAsync(directory, cancellationToken);
        }

        foreach (string file in _fileSystem.Directory.EnumerateFiles(_stagingRoot))
        {
            try
            {
                _fileSystem.File.Delete(file);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }

        return Task.CompletedTask;
    }

    public Task<bool> ExistsAsync(string pluginId, Version version, CancellationToken cancellationToken = default)
    {
        ValidatePluginId(pluginId);
        ArgumentNullException.ThrowIfNull(version);
        return Task.FromResult(_fileSystem.Directory.Exists(GetArtifactPath(pluginId, version)));
    }

    public Task<ExtractedPackage?> OpenAsync(
        string pluginId,
        Version version,
        CancellationToken cancellationToken = default)
    {
        ValidatePluginId(pluginId);
        ArgumentNullException.ThrowIfNull(version);

        string directory = GetArtifactPath(pluginId, version);
        if (!_fileSystem.Directory.Exists(directory))
        {
            return Task.FromResult<ExtractedPackage?>(null);
        }

        List<PackageEntry> entries = [];
        byte[]? manifestBytes = null;
        byte[]? signatureBytes = null;

        foreach (string file in _fileSystem.Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories))
        {
            cancellationToken.ThrowIfCancellationRequested();

            string relative = _fileSystem.Path.GetRelativePath(directory, file).Replace('\\', '/');
            using Stream stream = _fileSystem.File.OpenRead(file);
            string hash = Convert.ToHexStringLower(SHA256.HashData(stream));
            entries.Add(new PackageEntry(relative, _fileSystem.FileInfo.New(file).Length, hash));

            if (string.Equals(relative, PackageLayout.ManifestFileName, StringComparison.Ordinal))
            {
                manifestBytes = _fileSystem.File.ReadAllBytes(file);
            }
            else if (string.Equals(relative, PackageLayout.SignatureFileName, StringComparison.Ordinal))
            {
                signatureBytes = _fileSystem.File.ReadAllBytes(file);
            }
        }

        return Task.FromResult<ExtractedPackage?>(new ExtractedPackage(directory, entries, manifestBytes, signatureBytes));
    }

    private string GetArtifactPath(string pluginId, Version version) =>
        _fileSystem.Path.Combine(_artifactsRoot, pluginId, version.ToString());

    private string ComputeArtifactHash(string directory)
    {
        List<PackageEntry> entries = [];
        foreach (string file in _fileSystem.Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories))
        {
            string relative = _fileSystem.Path.GetRelativePath(directory, file).Replace('\\', '/');
            using Stream stream = _fileSystem.File.OpenRead(file);
            string hash = Convert.ToHexStringLower(SHA256.HashData(stream));
            entries.Add(new PackageEntry(relative, _fileSystem.FileInfo.New(file).Length, hash));
        }

        return CanonicalPackageDigest.Format(CanonicalPackageDigest.ComputeHash(entries));
    }

    private void CopyDirectory(string source, string destination)
    {
        _fileSystem.Directory.CreateDirectory(destination);

        foreach (string file in _fileSystem.Directory.EnumerateFiles(source))
        {
            _fileSystem.File.Copy(
                file,
                _fileSystem.Path.Combine(destination, _fileSystem.Path.GetFileName(file)),
                overwrite: true);
        }

        foreach (string directory in _fileSystem.Directory.EnumerateDirectories(source))
        {
            CopyDirectory(directory, _fileSystem.Path.Combine(destination, _fileSystem.Path.GetFileName(directory)));
        }
    }

    private void ValidatePluginId(string pluginId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pluginId);

        if (pluginId is "." or ".."
            || pluginId.IndexOfAny(_fileSystem.Path.GetInvalidFileNameChars()) >= 0
            || pluginId.Contains('/')
            || pluginId.Contains('\\'))
        {
            throw new InvalidOperationException($"Plugin id '{pluginId}' is not a valid storage segment.");
        }
    }
}

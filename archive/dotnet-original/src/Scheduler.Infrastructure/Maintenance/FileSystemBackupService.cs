using System.IO.Abstractions;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Data.Sqlite;
using Scheduler.Application.Maintenance;
using Scheduler.Infrastructure.Packaging;
using Scheduler.Infrastructure.Persistence;

namespace Scheduler.Infrastructure.Maintenance;

/// <summary>
/// A consistent backup of the authoritative state: <c>VACUUM INTO</c> takes a
/// transactionally consistent snapshot of the registry (lifecycle and
/// activation rows included), the artifact store is copied alongside it, and a
/// hash manifest records every artifact so a restore can be verified.
/// </summary>
public sealed class FileSystemBackupService : IBackupService
{
    private const string DatabaseFile = "registry.db";
    private const string ArtifactsDirectory = "artifacts";
    private const string ManifestFile = "manifest.json";

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly IFileSystem _fileSystem;
    private readonly ISqliteConnectionFactory _connectionFactory;
    private readonly string _artifactsRoot;
    private readonly string _backupRoot;
    private readonly string? _baseDirectory;

    public FileSystemBackupService(
        IFileSystem fileSystem,
        ISqliteConnectionFactory connectionFactory,
        PackagingOptions packagingOptions)
    {
        ArgumentNullException.ThrowIfNull(fileSystem);
        ArgumentNullException.ThrowIfNull(connectionFactory);
        ArgumentNullException.ThrowIfNull(packagingOptions);

        _fileSystem = fileSystem;
        _connectionFactory = connectionFactory;
        _baseDirectory = packagingOptions.BaseDirectory;
        _artifactsRoot = PackagingPaths.Resolve(
            packagingOptions.ArtifactsRoot,
            packagingOptions.BaseDirectory,
            fileSystem);
        _backupRoot = PackagingPaths.Resolve(
            packagingOptions.BackupRoot,
            packagingOptions.BaseDirectory,
            fileSystem);
    }

    public async Task<BackupResult> CreateAsync(
        string destinationRoot,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(destinationRoot);

        string destination = PackagingPaths.Resolve(destinationRoot, _baseDirectory, _fileSystem);
        if (!PackagingPaths.IsWithin(destination, _backupRoot, _fileSystem))
        {
            throw new ArgumentException(
                $"Backup destination '{destination}' must be within the configured backup root '{_backupRoot}'.",
                nameof(destinationRoot));
        }

        _fileSystem.Directory.CreateDirectory(destination);

        string databaseTarget = _fileSystem.Path.Combine(destination, DatabaseFile);
        if (_fileSystem.File.Exists(databaseTarget))
        {
            _fileSystem.File.Delete(databaseTarget);
        }

        await VacuumIntoAsync(databaseTarget, cancellationToken);

        // A reused destination must not retain artifacts from an earlier backup.
        string artifactsTarget = _fileSystem.Path.Combine(destination, ArtifactsDirectory);
        if (_fileSystem.Directory.Exists(artifactsTarget))
        {
            _fileSystem.Directory.Delete(artifactsTarget, recursive: true);
        }

        int artifactCount = CopyArtifacts(destination);
        WriteManifest(destination);

        BackupVerification verification = await VerifyAsync(destination, cancellationToken);
        return new BackupResult(destination, artifactCount, verification.Verified);
    }

    public Task<BackupVerification> VerifyAsync(
        string backupRoot,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(backupRoot);
        cancellationToken.ThrowIfCancellationRequested();

        string root = _fileSystem.Path.GetFullPath(backupRoot);
        string manifestPath = _fileSystem.Path.Combine(root, ManifestFile);
        if (!_fileSystem.File.Exists(manifestPath))
        {
            return Task.FromResult(new BackupVerification(false, 0, ["Backup manifest is missing."]));
        }

        Manifest manifest = JsonSerializer.Deserialize<Manifest>(_fileSystem.File.ReadAllText(manifestPath), JsonOptions)
            ?? new Manifest([]);

        List<string> failures = [];
        if (!_fileSystem.File.Exists(_fileSystem.Path.Combine(root, DatabaseFile)))
        {
            failures.Add($"missing: {DatabaseFile}");
        }

        int verified = 0;
        foreach (ManifestEntry entry in manifest.Entries)
        {
            string path = _fileSystem.Path.Combine(root, entry.Path);
            if (!_fileSystem.File.Exists(path))
            {
                failures.Add($"missing: {entry.Path}");
                continue;
            }

            string actual = HashFile(path);
            if (!string.Equals(actual, entry.Sha256, StringComparison.Ordinal))
            {
                failures.Add($"hash mismatch: {entry.Path}");
                continue;
            }

            verified++;
        }

        return Task.FromResult(new BackupVerification(failures.Count == 0, verified, failures));
    }

    private async Task VacuumIntoAsync(string databaseTarget, CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = await _connectionFactory.OpenConnectionAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "VACUUM INTO $target;";
        command.Parameters.AddWithValue("$target", databaseTarget);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private int CopyArtifacts(string destination)
    {
        if (!_fileSystem.Directory.Exists(_artifactsRoot))
        {
            return 0;
        }

        string target = _fileSystem.Path.Combine(destination, ArtifactsDirectory);
        CopyDirectory(_artifactsRoot, target);
        return _fileSystem.Directory.EnumerateFiles(target, "*", SearchOption.AllDirectories).Count();
    }

    private void WriteManifest(string destination)
    {
        string artifactsTarget = _fileSystem.Path.Combine(destination, ArtifactsDirectory);
        List<ManifestEntry> entries = [];
        if (_fileSystem.Directory.Exists(artifactsTarget))
        {
            foreach (string file in _fileSystem.Directory.EnumerateFiles(artifactsTarget, "*", SearchOption.AllDirectories))
            {
                string relative = _fileSystem.Path.GetRelativePath(destination, file).Replace('\\', '/');
                entries.Add(new ManifestEntry(relative, HashFile(file)));
            }
        }

        entries.Sort((left, right) => string.CompareOrdinal(left.Path, right.Path));
        _fileSystem.File.WriteAllText(
            _fileSystem.Path.Combine(destination, ManifestFile),
            JsonSerializer.Serialize(new Manifest(entries), JsonOptions));
    }

    private string HashFile(string path)
    {
        using Stream stream = _fileSystem.File.OpenRead(path);
        return "sha256:" + Convert.ToHexStringLower(SHA256.HashData(stream));
    }

    private void CopyDirectory(string source, string destination)
    {
        _fileSystem.Directory.CreateDirectory(destination);

        foreach (string file in _fileSystem.Directory.EnumerateFiles(source))
        {
            _fileSystem.File.Copy(file, _fileSystem.Path.Combine(destination, _fileSystem.Path.GetFileName(file)), overwrite: true);
        }

        foreach (string directory in _fileSystem.Directory.EnumerateDirectories(source))
        {
            CopyDirectory(directory, _fileSystem.Path.Combine(destination, _fileSystem.Path.GetFileName(directory)));
        }
    }

    private sealed record Manifest(
        [property: JsonPropertyName("entries")] IReadOnlyList<ManifestEntry> Entries);

    private sealed record ManifestEntry(
        [property: JsonPropertyName("path")] string Path,
        [property: JsonPropertyName("sha256")] string Sha256);
}

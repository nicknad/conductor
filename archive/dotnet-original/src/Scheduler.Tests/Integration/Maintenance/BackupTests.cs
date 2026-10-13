using System.IO.Abstractions;
using Microsoft.Data.Sqlite;
using Scheduler.Application.Maintenance;
using Scheduler.Application.Persistence;
using Scheduler.Application.PluginManagement;
using Scheduler.Infrastructure.Maintenance;
using Scheduler.Infrastructure.Packaging;
using Scheduler.Infrastructure.Persistence;

namespace Scheduler.Tests.Integration.Maintenance;

public sealed class BackupTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task BackupVerifiesArtifactHashesAndPreservesActivationState()
    {
        string root = CreateTempDirectory();
        using SqliteTestDatabase database = new();
        try
        {
            await database.InitializeAsync(Ct);
            await SeedActivePluginAsync(database);

            string artifactsRoot = Path.Combine(root, "artifacts");
            WriteArtifact(artifactsRoot, "plugin-1", "1.0.0", "plugin.json", "{\"id\":\"plugin-1\"}");
            WriteArtifact(artifactsRoot, "plugin-1", "1.0.0", "Plugin.dll", "binary-payload");

            FileSystem fileSystem = new();
            PackagingOptions packagingOptions = new()
            {
                ArtifactsRoot = artifactsRoot,
                StagingRoot = Path.Combine(root, "staging"),
                PublicKeyPath = Path.Combine(root, "public.pem"),
                BackupRoot = Path.Combine(root, "backups"),
                BaseDirectory = root,
            };
            FileSystemBackupService backup = new(fileSystem, database.ConnectionFactory, packagingOptions);

            string destination = Path.Combine(root, "backups", "snapshot");
            BackupResult result = await backup.CreateAsync(destination, Ct);

            Assert.True(result.Verified);
            Assert.Equal(2, result.ArtifactCount);
            Assert.True((await backup.VerifyAsync(destination, Ct)).Verified);

            PluginActivationRecord? activation = await ReadActivationAsync(destination);
            Assert.NotNull(activation);
            Assert.Equal(new Version(1, 0, 0), activation.Version);

            PluginVersionRecord? version = await ReadVersionAsync(destination);
            Assert.NotNull(version);
            Assert.Equal(PluginLifecycleState.Active, version.State);
            Assert.Equal("sha256:test", version.ArtifactHash);

            Assert.Equal(
                File.ReadAllText(Path.Combine(artifactsRoot, "plugin-1", "1.0.0", "Plugin.dll")),
                File.ReadAllText(Path.Combine(destination, "artifacts", "plugin-1", "1.0.0", "Plugin.dll")));

            // A reused destination must not retain artifacts from an earlier backup.
            File.WriteAllText(Path.Combine(destination, "artifacts", "stale.bin"), "stale");
            SqliteConnection.ClearAllPools();
            await backup.CreateAsync(destination, Ct);
            Assert.False(File.Exists(Path.Combine(destination, "artifacts", "stale.bin")));

            // Tampering with a backed-up artifact breaks verification.
            File.AppendAllText(Path.Combine(destination, "artifacts", "plugin-1", "1.0.0", "Plugin.dll"), "tampered");
            Assert.False((await backup.VerifyAsync(destination, Ct)).Verified);

            // A missing database breaks verification.
            SqliteConnection.ClearAllPools();
            File.Delete(Path.Combine(destination, "registry.db"));
            Assert.False((await backup.VerifyAsync(destination, Ct)).Verified);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task BackupDestinationOutsideTheBackupRootIsRejected()
    {
        string root = CreateTempDirectory();
        using SqliteTestDatabase database = new();
        try
        {
            await database.InitializeAsync(Ct);
            FileSystem fileSystem = new();
            PackagingOptions packagingOptions = new()
            {
                ArtifactsRoot = Path.Combine(root, "artifacts"),
                StagingRoot = Path.Combine(root, "staging"),
                PublicKeyPath = Path.Combine(root, "public.pem"),
                BackupRoot = Path.Combine(root, "backups"),
                BaseDirectory = root,
            };
            FileSystemBackupService backup = new(fileSystem, database.ConnectionFactory, packagingOptions);

            await Assert.ThrowsAsync<ArgumentException>(
                () => backup.CreateAsync(Path.Combine(root, "elsewhere"), Ct));
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            Directory.Delete(root, recursive: true);
        }
    }

    private static async Task SeedActivePluginAsync(SqliteTestDatabase database)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        await using IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(Ct);
        await unitOfWork.Plugins.UpsertVersionAsync(
            new PluginVersionRecord
            {
                PluginId = "plugin-1",
                Version = new Version(1, 0, 0),
                ContractVersion = "1.0",
                EntryAssembly = "Plugin.dll",
                EntryType = "Plugin.Entry",
                ExecutionMode = Contracts.Execution.ExecutionMode.InProcess,
                ArtifactHash = "sha256:test",
                State = PluginLifecycleState.Active,
                InstalledAt = now,
                ValidatedAt = now,
            },
            Ct);
        await unitOfWork.Plugins.SetActivationAsync(
            new PluginActivationRecord
            {
                PluginId = "plugin-1",
                Version = new Version(1, 0, 0),
                ActivatedAt = now,
                ActivatedBy = "test",
            },
            Ct);
        await unitOfWork.CommitAsync(Ct);
    }

    private static async Task<PluginActivationRecord?> ReadActivationAsync(string backupRoot)
    {
        PersistenceOptions options = new() { DatabasePath = Path.Combine(backupRoot, "registry.db") };
        SqliteConnectionFactory factory = new(options, new FileSystem());
        SqliteRegistryUnitOfWorkFactory unitOfWorkFactory = new(factory);
        await using IRegistryUnitOfWork unitOfWork = await unitOfWorkFactory.BeginAsync(Ct);
        return await unitOfWork.Plugins.GetActivationAsync("plugin-1", Ct);
    }

    private static async Task<PluginVersionRecord?> ReadVersionAsync(string backupRoot)
    {
        PersistenceOptions options = new() { DatabasePath = Path.Combine(backupRoot, "registry.db") };
        SqliteConnectionFactory factory = new(options, new FileSystem());
        SqliteRegistryUnitOfWorkFactory unitOfWorkFactory = new(factory);
        await using IRegistryUnitOfWork unitOfWork = await unitOfWorkFactory.BeginAsync(Ct);
        return await unitOfWork.Plugins.GetVersionAsync("plugin-1", new Version(1, 0, 0), Ct);
    }

    private static void WriteArtifact(string root, string pluginId, string version, string fileName, string content)
    {
        string directory = Path.Combine(root, pluginId, version);
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, fileName), content);
    }

    private static string CreateTempDirectory()
    {
        string directory = Path.Combine(Path.GetTempPath(), "jobscheduler-backup", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        return directory;
    }
}

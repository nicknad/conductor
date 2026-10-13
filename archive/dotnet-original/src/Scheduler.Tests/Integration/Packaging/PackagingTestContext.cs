using System.IO.Abstractions;
using Scheduler.Application.Execution;
using Scheduler.Application.Packaging;
using Scheduler.Application.Persistence;
using Scheduler.Application.PluginManagement;
using Scheduler.Contracts;
using Scheduler.Infrastructure.Packaging;
using Scheduler.Runtime.InProcess.AssemblyLoading;
using Scheduler.Tests.Integration;

namespace Scheduler.Tests.Integration.Packaging;

/// <summary>
/// A throwaway registry + artifact/staging store wired into a real
/// <see cref="PluginManager" /> for install/validation integration tests.
/// </summary>
internal sealed class PackagingTestContext : IDisposable
{
    private readonly SqliteTestDatabase _database;
    private readonly string _directory;

    public PackagingTestContext(string publicKeyPath, PackagingLimits? limits = null)
    {
        _directory = Path.Combine(Path.GetTempPath(), "jobscheduler-packaging", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_directory);

        _database = new SqliteTestDatabase();
        FileSystem = new FileSystem();
        Options = new PackagingOptions
        {
            ArtifactsRoot = Path.Combine(_directory, "artifacts"),
            StagingRoot = Path.Combine(_directory, "staging"),
            PublicKeyPath = publicKeyPath,
            DataRoot = Path.Combine(_directory, "data"),
            LogsRoot = Path.Combine(_directory, "logs"),
            BaseDirectory = _directory,
        };

        ArtifactStore = new FileSystemArtifactStore(Options, FileSystem);
        PackageSignatureVerifier verifier = new(Options, FileSystem);
        PackageValidator validator = new(verifier);
        ZipPackageArchiveReader reader = new(FileSystem);
        AuditWriter audit = new(_database.UnitOfWorkFactory, TimeProvider);
        Runtime = new InProcessPluginRuntime();
        RunningExecutions = new RunningExecutionRegistry(TimeProvider);
        Manager = new PluginManager(
            _database.UnitOfWorkFactory,
            reader,
            ArtifactStore,
            validator,
            audit,
            TimeProvider,
            limits ?? Options.ToLimits(),
            SchedulerContract.CurrentVersion,
            Runtime,
            RunningExecutions,
            ExecutionOptions);
    }

    public IFileSystem FileSystem { get; }

    public PackagingOptions Options { get; }

    public IArtifactStore ArtifactStore { get; }

    public PluginManager Manager { get; }

    public IPluginRuntime Runtime { get; }

    public IRunningExecutionRegistry RunningExecutions { get; }

    public ExecutionOptions ExecutionOptions { get; } = new();

    public TimeProvider TimeProvider { get; } = TimeProvider.System;

    public IRegistryUnitOfWorkFactory UnitOfWorkFactory => _database.UnitOfWorkFactory;

    public Task InitializeAsync(CancellationToken cancellationToken = default) =>
        _database.InitializeAsync(cancellationToken);

    public void Dispose()
    {
        _database.Dispose();

        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (DirectoryNotFoundException)
        {
        }
        catch (IOException)
        {
        }
    }
}

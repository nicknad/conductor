using System.IO.Abstractions;
using Scheduler.Application.Execution;
using Scheduler.Application.JobManagement;
using Scheduler.Application.Observability;
using Scheduler.Application.Packaging;
using Scheduler.Application.Persistence;
using Scheduler.Application.PluginManagement;
using Scheduler.Application.Secrets;
using Scheduler.Contracts;
using Scheduler.Contracts.Execution;
using Scheduler.Contracts.Jobs;
using Scheduler.Infrastructure.Packaging;
using Scheduler.Runtime.InProcess.AssemblyLoading;
using Scheduler.Runtime.InProcess.Execution;
using Scheduler.Tests.Integration;

namespace Scheduler.Tests.Integration.Execution;

/// <summary>
/// A throwaway registry + artifact store wired to the real plugin manager,
/// dispatcher, and job manager. The plugin runtime is injectable so dispatch
/// behavior can be tested with scripted handlers.
/// </summary>
internal sealed class RuntimeTestContext : IDisposable
{
    private readonly SqliteTestDatabase _database;
    private readonly string _directory;

    public RuntimeTestContext(
        string publicKeyPath,
        IPluginRuntime? runtime = null,
        ExecutionOptions? executionOptions = null,
        ISecretValueStore? secretValueStore = null)
    {
        _directory = Path.Combine(Path.GetTempPath(), "jobscheduler-runtime", Guid.NewGuid().ToString("N"));
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
        ExecutionOptions = executionOptions ?? new ExecutionOptions();

        ArtifactStore = new FileSystemArtifactStore(Options, FileSystem);
        PackageValidator validator = new(new PackageSignatureVerifier(Options, FileSystem));
        AuditWriter audit = new(_database.UnitOfWorkFactory, TimeProvider);
        Runtime = runtime ?? new InProcessPluginRuntime();
        RunningExecutions = new RunningExecutionRegistry(TimeProvider);
        Shutdown = new ShutdownSignal();
        Gate = new ConcurrencyGate(ExecutionOptions);
        RetryEvaluator = new RetryPolicyEvaluator();

        Manager = new PluginManager(
            _database.UnitOfWorkFactory,
            new ZipPackageArchiveReader(FileSystem),
            ArtifactStore,
            validator,
            audit,
            TimeProvider,
            Options.ToLimits(),
            SchedulerContract.CurrentVersion,
            Runtime,
            RunningExecutions,
            ExecutionOptions);

        IExecutionBackend backend = new InProcessExecutionBackend(new NullExecutionLoggerFactory());
        ISecretProviderFactory secretProviderFactory = secretValueStore is null
            ? new DeniedSecretProviderFactory()
            : new RegistrySecretProviderFactory(_database.UnitOfWorkFactory, secretValueStore, audit);
        Runner = new ExecutionRunner(_database.UnitOfWorkFactory, backend, secretProviderFactory, RetryEvaluator, TimeProvider);
        Dispatcher = new Dispatcher(
            _database.UnitOfWorkFactory,
            Runtime,
            backend,
            Runner,
            Gate,
            RunningExecutions,
            new ExecutionRejectionWriter(_database.UnitOfWorkFactory, TimeProvider),
            Shutdown,
            TimeProvider);
        Jobs = new JobManager(_database.UnitOfWorkFactory, Dispatcher, audit, TimeProvider);
    }

    public IFileSystem FileSystem { get; }

    public PackagingOptions Options { get; }

    public ExecutionOptions ExecutionOptions { get; }

    public IArtifactStore ArtifactStore { get; }

    public IPluginRuntime Runtime { get; }

    public IRunningExecutionRegistry RunningExecutions { get; }

    public ShutdownSignal Shutdown { get; }

    public ConcurrencyGate Gate { get; }

    public RetryPolicyEvaluator RetryEvaluator { get; }

    public ExecutionRunner Runner { get; }

    public Dispatcher Dispatcher { get; }

    public JobManager Jobs { get; }

    public PluginManager Manager { get; }

    public TimeProvider TimeProvider { get; } = TimeProvider.System;

    public IRegistryUnitOfWorkFactory UnitOfWorkFactory => _database.UnitOfWorkFactory;

    public Task InitializeAsync(CancellationToken cancellationToken = default) =>
        _database.InitializeAsync(cancellationToken);

    public async Task SeedActivePluginAsync(
        string pluginId,
        Version version,
        JobDefinition definition,
        CancellationToken cancellationToken = default)
    {
        await using IRegistryUnitOfWork unitOfWork = await UnitOfWorkFactory.BeginAsync(cancellationToken);
        await unitOfWork.Plugins.UpsertVersionAsync(
            new PluginVersionRecord
            {
                PluginId = pluginId,
                Version = version,
                ContractVersion = "1.0",
                EntryAssembly = "test.dll",
                EntryType = "Test.Plugin",
                ExecutionMode = definition.ExecutionMode,
                ArtifactHash = "sha256:test",
                State = PluginLifecycleState.Active,
                InstalledAt = TimeProvider.GetUtcNow(),
                ValidatedAt = TimeProvider.GetUtcNow(),
            },
            cancellationToken);
        await unitOfWork.Plugins.SetActivationAsync(
            new PluginActivationRecord
            {
                PluginId = pluginId,
                Version = version,
                ActivatedAt = TimeProvider.GetUtcNow(),
                ActivatedBy = "test",
            },
            cancellationToken);
        await unitOfWork.Jobs.UpsertAsync(
            new JobRecord
            {
                Definition = definition,
                ConfigurationRevision = 1,
                UpdatedAt = TimeProvider.GetUtcNow(),
            },
            cancellationToken);
        await unitOfWork.CommitAsync(cancellationToken);
    }

    public async Task<ExecutionRecord?> ReadExecutionAsync(Guid executionId, CancellationToken cancellationToken = default)
    {
        await using IRegistryUnitOfWork unitOfWork = await UnitOfWorkFactory.BeginAsync(cancellationToken);
        return await unitOfWork.Executions.GetAsync(executionId, cancellationToken);
    }

    public async Task<PluginVersionRecord?> ReadVersionAsync(
        string pluginId,
        Version version,
        CancellationToken cancellationToken = default)
    {
        await using IRegistryUnitOfWork unitOfWork = await UnitOfWorkFactory.BeginAsync(cancellationToken);
        return await unitOfWork.Plugins.GetVersionAsync(pluginId, version, cancellationToken);
    }

    public async Task<PluginActivationRecord?> ReadActivationAsync(
        string pluginId,
        CancellationToken cancellationToken = default)
    {
        await using IRegistryUnitOfWork unitOfWork = await UnitOfWorkFactory.BeginAsync(cancellationToken);
        return await unitOfWork.Plugins.GetActivationAsync(pluginId, cancellationToken);
    }

    public void Dispose()
    {
        Gate.Dispose();
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
        catch (UnauthorizedAccessException)
        {
        }
    }
}

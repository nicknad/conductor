using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Quartz;
using Scheduler.Application.Execution;
using Scheduler.Application.JobManagement;
using Scheduler.Application.Observability;
using Scheduler.Application.Persistence;
using Scheduler.Application.PluginManagement;
using Scheduler.Application.Reconciliation;
using Scheduler.Contracts.Execution;
using Scheduler.Contracts.Jobs;
using Scheduler.Infrastructure.Observability;
using Scheduler.Infrastructure.Persistence;
using Scheduler.Infrastructure.Scheduling;
using Scheduler.Tests.Support;

namespace Scheduler.Tests.Integration.Scheduling;

/// <summary>
/// A throwaway registry database plus a real Quartz scheduler (RAM or the ADO.NET
/// SQLite store), the real reconciler, and the real job manager. Registry state
/// can be seeded directly or written through the manager so both the outbox and
/// reconciliation paths are exercised. Every temp directory is deleted on dispose.
/// </summary>
internal sealed class QuartzScheduleTestContext : IAsyncDisposable
{
    private readonly ServiceProvider _provider;
    private readonly bool _ownsDatabase;

    private QuartzScheduleTestContext(
        ServiceProvider provider,
        SqliteTestDatabase database,
        bool ownsDatabase,
        ScheduleOptions options,
        IScheduler scheduler,
        IReconciler reconciler,
        IReconciliationStatus reconciliationStatus,
        IScheduleStore scheduleStore,
        IJobManager jobs,
        RecordingDispatcher dispatcher)
    {
        _provider = provider;
        _ownsDatabase = ownsDatabase;
        Database = database;
        Options = options;
        Scheduler = scheduler;
        Reconciler = reconciler;
        ReconciliationStatus = reconciliationStatus;
        ScheduleStore = scheduleStore;
        Jobs = jobs;
        Dispatcher = dispatcher;
    }

    public SqliteTestDatabase Database { get; }

    public ScheduleOptions Options { get; }

    public IScheduler Scheduler { get; }

    public IReconciler Reconciler { get; }

    public IReconciliationStatus ReconciliationStatus { get; }

    public IScheduleStore ScheduleStore { get; }

    public IJobManager Jobs { get; }

    public RecordingDispatcher Dispatcher { get; }

    public IRegistryUnitOfWorkFactory UnitOfWorkFactory => Database.UnitOfWorkFactory;

    public static Task<QuartzScheduleTestContext> CreateAsync(
        bool persistent = false,
        ScheduleOptions? options = null,
        CancellationToken cancellationToken = default) =>
        CreateAsync(new SqliteTestDatabase(), ownsDatabase: true, persistent, options, cancellationToken);

    public static async Task<QuartzScheduleTestContext> CreateAsync(
        SqliteTestDatabase database,
        bool ownsDatabase,
        bool persistent = false,
        ScheduleOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(database);
        if (ownsDatabase)
        {
            await database.InitializeAsync(cancellationToken);
        }

        ScheduleOptions effectiveOptions = options ?? new ScheduleOptions { UsePersistentStore = persistent };
        RecordingDispatcher dispatcher = new();
        ServiceCollection services = new();
        services.AddSingleton<ILoggerFactory>(NullLoggerFactory.Instance);
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        services.AddSingleton(TimeProvider.System);
        services.AddSingleton<IRegistryUnitOfWorkFactory>(database.UnitOfWorkFactory);
        services.AddSingleton<IAuditWriter>(new AuditWriter(database.UnitOfWorkFactory, TimeProvider.System));
        services.AddSingleton<IDispatcher>(dispatcher);
        services.AddSingleton<IJobManager, JobManager>();
        services.AddSchedulerScheduling(database.ConnectionFactory.DatabasePath, effectiveOptions);
        services.AddSchedulerObservability(new ObservabilityOptions());

        ServiceProvider provider = services.BuildServiceProvider();
        ISchedulerFactory factory = provider.GetRequiredService<ISchedulerFactory>();
        IScheduler scheduler = await factory.GetScheduler(cancellationToken);
        await scheduler.Start(cancellationToken);

        return new QuartzScheduleTestContext(
            provider,
            database,
            ownsDatabase,
            effectiveOptions,
            scheduler,
            provider.GetRequiredService<IReconciler>(),
            provider.GetRequiredService<IReconciliationStatus>(),
            provider.GetRequiredService<IScheduleStore>(),
            provider.GetRequiredService<IJobManager>(),
            dispatcher);
    }

    public async Task SeedActivePluginAsync(
        string pluginId,
        Version version,
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
                ExecutionMode = ExecutionMode.InProcess,
                ArtifactHash = "sha256:test",
                State = PluginLifecycleState.Active,
                InstalledAt = DateTimeOffset.UnixEpoch,
                ValidatedAt = DateTimeOffset.UnixEpoch,
            },
            cancellationToken);
        await unitOfWork.Plugins.SetActivationAsync(
            new PluginActivationRecord
            {
                PluginId = pluginId,
                Version = version,
                ActivatedAt = DateTimeOffset.UnixEpoch,
                ActivatedBy = "test",
            },
            cancellationToken);
        await unitOfWork.CommitAsync(cancellationToken);
    }

    public async Task SeedStagedPluginAsync(
        string pluginId,
        Version version,
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
                ExecutionMode = ExecutionMode.InProcess,
                ArtifactHash = "sha256:test",
                State = PluginLifecycleState.Staged,
                InstalledAt = DateTimeOffset.UnixEpoch,
                ValidatedAt = DateTimeOffset.UnixEpoch,
            },
            cancellationToken);
        await unitOfWork.CommitAsync(cancellationToken);
    }

    public async Task SeedJobAsync(JobRecord job, CancellationToken cancellationToken = default)
    {
        await using IRegistryUnitOfWork unitOfWork = await UnitOfWorkFactory.BeginAsync(cancellationToken);
        await unitOfWork.Jobs.UpsertAsync(job, cancellationToken);
        await unitOfWork.CommitAsync(cancellationToken);
    }

    public async Task SetJobEnabledAsync(string jobId, bool enabled, CancellationToken cancellationToken = default)
    {
        await using IRegistryUnitOfWork unitOfWork = await UnitOfWorkFactory.BeginAsync(cancellationToken);
        await unitOfWork.Jobs.SetEnabledAsync(jobId, enabled, DateTimeOffset.UnixEpoch, cancellationToken);
        await unitOfWork.CommitAsync(cancellationToken);
    }

    public async Task ClearActivationAsync(string pluginId, CancellationToken cancellationToken = default)
    {
        await using IRegistryUnitOfWork unitOfWork = await UnitOfWorkFactory.BeginAsync(cancellationToken);
        await unitOfWork.Plugins.ClearActivationAsync(pluginId, cancellationToken);
        await unitOfWork.CommitAsync(cancellationToken);
    }

    public async Task<ITrigger?> GetTriggerAsync(string jobId, CancellationToken cancellationToken = default)
    {
        return await Scheduler.GetTrigger(new TriggerKey(jobId, Options.JobGroup), cancellationToken);
    }

    public async Task<IReadOnlyList<string?>> ReadRawTriggerJobDataAsync(CancellationToken cancellationToken = default)
    {
        await using SqliteConnection connection = await Database.ConnectionFactory.OpenConnectionAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "SELECT JOB_DATA FROM QRTZ_TRIGGERS;";

        List<string?> data = [];
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            data.Add(reader.IsDBNull(0) ? null : System.Text.Encoding.UTF8.GetString((byte[])reader.GetValue(0)));
        }

        return data;
    }

    public async Task CreateOperationAsync(OperationRecord operation, CancellationToken cancellationToken = default)
    {
        await using IRegistryUnitOfWork unitOfWork = await UnitOfWorkFactory.BeginAsync(cancellationToken);
        await unitOfWork.Operations.CreateAsync(operation, cancellationToken);
        await unitOfWork.CommitAsync(cancellationToken);
    }

    public async Task<OperationRecord?> ReadOperationAsync(Guid operationId, CancellationToken cancellationToken = default)
    {
        await using IRegistryUnitOfWork unitOfWork = await UnitOfWorkFactory.BeginAsync(cancellationToken);
        return await unitOfWork.Operations.GetAsync(operationId, cancellationToken);
    }

    public async Task TransitionOperationAsync(
        Guid operationId,
        OperationState state,
        CancellationToken cancellationToken = default)
    {
        await using IRegistryUnitOfWork unitOfWork = await UnitOfWorkFactory.BeginAsync(cancellationToken);
        await unitOfWork.Operations.UpdateStateAsync(
            operationId,
            state,
            payload: null,
            DateTimeOffset.UnixEpoch,
            cancellationToken);
        await unitOfWork.CommitAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<ScheduledJob>> ListScheduledAsync(CancellationToken cancellationToken = default)
    {
        return await ScheduleStore.ListAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<string>> ListQuartzTablesAsync(CancellationToken cancellationToken = default)
    {
        await using SqliteConnection connection = await Database.ConnectionFactory.OpenConnectionAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'QRTZ_%' ORDER BY name;";

        List<string> tables = [];
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            tables.Add(reader.GetString(0));
        }

        return tables;
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            await Scheduler.Shutdown(waitForJobsToComplete: false);
        }
        catch (Exception)
        {
        }

        await _provider.DisposeAsync();

        if (_ownsDatabase)
        {
            Database.Dispose();
        }
    }
}

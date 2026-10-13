using Microsoft.Data.Sqlite;
using Scheduler.Application.Persistence;
using Scheduler.Application.PluginManagement;
using Scheduler.Contracts.Execution;

namespace Scheduler.Tests.Integration;

public sealed class OperationRepositoryTests
{
    private static readonly DateTimeOffset CreatedAt = new(2026, 4, 5, 6, 7, 8, TimeSpan.Zero);

    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task LifecyclePersistsAcrossTransactions()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);

        OperationRecord operation = NewOperation();
        await CreateAsync(database, operation);

        await TransitionAsync(database, operation.OperationId, OperationState.Running, payload: null);
        await TransitionAsync(database, operation.OperationId, OperationState.Succeeded, "published");

        await using IRegistryUnitOfWork read = await database.UnitOfWorkFactory.BeginAsync(CancellationToken);
        OperationRecord? reloaded = await read.Operations.GetAsync(operation.OperationId, CancellationToken);

        Assert.NotNull(reloaded);
        Assert.Equal(OperationState.Succeeded, reloaded.State);
        Assert.Equal("published", reloaded.Payload);
    }

    [Theory]
    [InlineData(OperationState.Failed)]
    [InlineData(OperationState.RolledBack)]
    public async Task TerminalStatesRejectFurtherTransitions(OperationState terminalState)
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);

        OperationRecord operation = NewOperation();
        await CreateAsync(database, operation);

        await TransitionAsync(database, operation.OperationId, OperationState.Running, payload: null);
        await TransitionAsync(database, operation.OperationId, terminalState, "finished");

        await using IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken);
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => unitOfWork.Operations.UpdateStateAsync(
                operation.OperationId,
                OperationState.Running,
                payload: null,
                CreatedAt.AddMinutes(2),
                CancellationToken));

        OperationRecord? reloaded = await unitOfWork.Operations.GetAsync(operation.OperationId, CancellationToken);
        Assert.NotNull(reloaded);
        Assert.Equal(terminalState, reloaded.State);
        Assert.Equal("finished", reloaded.Payload);
    }

    [Fact]
    public async Task InvalidTransitionIsRejected()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);

        OperationRecord operation = NewOperation();
        await CreateAsync(database, operation);
        await TransitionAsync(database, operation.OperationId, OperationState.Running, payload: null);
        await TransitionAsync(database, operation.OperationId, OperationState.Succeeded, "done");

        await using IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => unitOfWork.Operations.UpdateStateAsync(
                operation.OperationId,
                OperationState.Running,
                payload: "illegal",
                CreatedAt.AddMinutes(1),
                CancellationToken));

        OperationRecord? reloaded = await unitOfWork.Operations.GetAsync(operation.OperationId, CancellationToken);
        Assert.NotNull(reloaded);
        Assert.Equal(OperationState.Succeeded, reloaded.State);
        Assert.Equal("done", reloaded.Payload);
    }

    [Fact]
    public async Task NonTerminalListingExcludesCompletedOperations()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);

        OperationRecord pending = NewOperation();
        OperationRecord completed = NewOperation();
        await CreateAsync(database, pending);
        await CreateAsync(database, completed);
        await TransitionAsync(database, completed.OperationId, OperationState.Running, payload: null);
        await TransitionAsync(database, completed.OperationId, OperationState.Succeeded, payload: null);

        await using IRegistryUnitOfWork read = await database.UnitOfWorkFactory.BeginAsync(CancellationToken);
        IReadOnlyList<OperationRecord> outstanding = await read.Operations.ListNonTerminalAsync(CancellationToken);

        Assert.Single(outstanding);
        Assert.Equal(pending.OperationId, outstanding[0].OperationId);
    }

    [Fact]
    public async Task RegistryWriteAndOperationCommitTogether()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);

        PluginVersionRecord version = NewVersion();
        OperationRecord operation = NewOperation();

        await using (IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken))
        {
            await unitOfWork.Plugins.UpsertVersionAsync(version, CancellationToken);
            await unitOfWork.Operations.CreateAsync(operation, CancellationToken);
            await unitOfWork.CommitAsync(CancellationToken);
        }

        await using IRegistryUnitOfWork read = await database.UnitOfWorkFactory.BeginAsync(CancellationToken);
        Assert.NotNull(await read.Plugins.GetVersionAsync(version.PluginId, version.Version, CancellationToken));
        Assert.NotNull(await read.Operations.GetAsync(operation.OperationId, CancellationToken));
    }

    [Fact]
    public async Task MidTransactionFailureLeavesNeitherWriteCommitted()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);

        PluginVersionRecord version = NewVersion();
        OperationRecord operation = NewOperation();

        await Assert.ThrowsAsync<SqliteException>(async () =>
        {
            await using IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken);
            await unitOfWork.Plugins.UpsertVersionAsync(version, CancellationToken);
            await unitOfWork.Operations.CreateAsync(operation, CancellationToken);

            // A duplicate primary key forces a failure before commit.
            await unitOfWork.Operations.CreateAsync(operation, CancellationToken);
        });

        await using IRegistryUnitOfWork read = await database.UnitOfWorkFactory.BeginAsync(CancellationToken);
        Assert.Null(await read.Plugins.GetVersionAsync(version.PluginId, version.Version, CancellationToken));
        Assert.Null(await read.Operations.GetAsync(operation.OperationId, CancellationToken));
    }

    [Fact]
    public async Task UncommittedRegistryWriteAndOperationAreRolledBack()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);

        PluginVersionRecord version = NewVersion();
        OperationRecord operation = NewOperation();

        await using (IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken))
        {
            await unitOfWork.Plugins.UpsertVersionAsync(version, CancellationToken);
            await unitOfWork.Operations.CreateAsync(operation, CancellationToken);
        }

        await using IRegistryUnitOfWork read = await database.UnitOfWorkFactory.BeginAsync(CancellationToken);
        Assert.Null(await read.Plugins.GetVersionAsync(version.PluginId, version.Version, CancellationToken));
        Assert.Null(await read.Operations.GetAsync(operation.OperationId, CancellationToken));
    }

    private static async Task CreateAsync(SqliteTestDatabase database, OperationRecord operation)
    {
        await using IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken);
        await unitOfWork.Operations.CreateAsync(operation, CancellationToken);
        await unitOfWork.CommitAsync(CancellationToken);
    }

    private static async Task TransitionAsync(
        SqliteTestDatabase database,
        Guid operationId,
        OperationState state,
        string? payload)
    {
        await using IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken);
        await unitOfWork.Operations.UpdateStateAsync(operationId, state, payload, CreatedAt.AddMinutes(1), CancellationToken);
        await unitOfWork.CommitAsync(CancellationToken);
    }

    private static OperationRecord NewOperation() => new()
    {
        OperationId = Guid.NewGuid(),
        Kind = OperationKind.Activate,
        Payload = """{"pluginId":"monthly-report","version":"1.2.0"}""",
        State = OperationState.Pending,
        CreatedAt = CreatedAt,
        UpdatedAt = CreatedAt,
    };

    private static PluginVersionRecord NewVersion() => new()
    {
        PluginId = "monthly-report",
        Version = new Version(1, 2, 0),
        ContractVersion = "1.0",
        EntryAssembly = "MonthlyReport.dll",
        EntryType = "MonthlyReport.Plugin",
        ExecutionMode = ExecutionMode.InProcess,
        ArtifactHash = "sha256:abc123",
        State = PluginLifecycleState.Staged,
        InstalledAt = CreatedAt,
    };
}

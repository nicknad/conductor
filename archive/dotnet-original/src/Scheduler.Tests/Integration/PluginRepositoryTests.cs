using Scheduler.Application.Persistence;
using Scheduler.Application.PluginManagement;
using Scheduler.Contracts.Execution;

namespace Scheduler.Tests.Integration;

public sealed class PluginRepositoryTests
{
    private static readonly DateTimeOffset InstalledAt = new(2026, 1, 2, 3, 4, 5, TimeSpan.Zero);

    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task VersionRoundTrips()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);

        PluginVersionRecord version = NewVersion();
        await using (IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken))
        {
            await unitOfWork.Plugins.UpsertVersionAsync(version, CancellationToken);
            await unitOfWork.CommitAsync(CancellationToken);
        }

        await using IRegistryUnitOfWork read = await database.UnitOfWorkFactory.BeginAsync(CancellationToken);
        PluginVersionRecord? reloaded = await read.Plugins.GetVersionAsync(version.PluginId, version.Version, CancellationToken);

        Assert.NotNull(reloaded);
        Assert.Equal(version, reloaded);
    }

    [Fact]
    public async Task UpsertReplacesExistingVersion()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);

        PluginVersionRecord version = NewVersion();
        await using (IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken))
        {
            await unitOfWork.Plugins.UpsertVersionAsync(version, CancellationToken);
            await unitOfWork.CommitAsync(CancellationToken);
        }

        await using (IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken))
        {
            await unitOfWork.Plugins.UpsertVersionAsync(version with { State = PluginLifecycleState.Staged }, CancellationToken);
            await unitOfWork.CommitAsync(CancellationToken);
        }

        await using IRegistryUnitOfWork read = await database.UnitOfWorkFactory.BeginAsync(CancellationToken);
        PluginVersionRecord? reloaded = await read.Plugins.GetVersionAsync(version.PluginId, version.Version, CancellationToken);

        Assert.NotNull(reloaded);
        Assert.Equal(PluginLifecycleState.Staged, reloaded.State);
        Assert.Equal(version.ArtifactHash, reloaded.ArtifactHash);
    }

    [Fact]
    public async Task SetVersionStateUpdatesStateAndValidation()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);

        PluginVersionRecord version = NewVersion();
        DateTimeOffset validatedAt = InstalledAt.AddMinutes(5);
        await using (IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken))
        {
            await unitOfWork.Plugins.UpsertVersionAsync(version, CancellationToken);
            await unitOfWork.CommitAsync(CancellationToken);
        }

        await using (IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken))
        {
            await unitOfWork.Plugins.SetVersionStateAsync(
                version.PluginId,
                version.Version,
                PluginLifecycleState.Rejected,
                "bad signature",
                validatedAt,
                CancellationToken);
            await unitOfWork.CommitAsync(CancellationToken);
        }

        await using IRegistryUnitOfWork read = await database.UnitOfWorkFactory.BeginAsync(CancellationToken);
        PluginVersionRecord? reloaded = await read.Plugins.GetVersionAsync(version.PluginId, version.Version, CancellationToken);

        Assert.NotNull(reloaded);
        Assert.Equal(PluginLifecycleState.Rejected, reloaded.State);
        Assert.Equal("bad signature", reloaded.ValidationError);
        Assert.Equal(validatedAt, reloaded.ValidatedAt);
    }

    [Fact]
    public async Task ListsVersionsAndPluginIds()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);

        PluginVersionRecord first = NewVersion();
        await using (IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken))
        {
            await unitOfWork.Plugins.UpsertVersionAsync(first, CancellationToken);
            await unitOfWork.Plugins.UpsertVersionAsync(first with { Version = new Version(2, 0, 0) }, CancellationToken);
            await unitOfWork.CommitAsync(CancellationToken);
        }

        await using IRegistryUnitOfWork read = await database.UnitOfWorkFactory.BeginAsync(CancellationToken);

        IReadOnlyList<PluginVersionRecord> versions = await read.Plugins.ListVersionsAsync(first.PluginId, CancellationToken);
        IReadOnlyList<string> pluginIds = await read.Plugins.ListPluginIdsAsync(CancellationToken);

        Assert.Equal(2, versions.Count);
        Assert.Equal(new[] { first.PluginId }, pluginIds);
    }

    [Fact]
    public async Task ActivationRoundTripsAndClears()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);

        PluginActivationRecord activation = new()
        {
            PluginId = "monthly-report",
            Version = new Version(1, 2, 0),
            ActivatedAt = InstalledAt,
            ActivatedBy = "operator",
        };

        await using (IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken))
        {
            await unitOfWork.Plugins.SetActivationAsync(activation, CancellationToken);
            await unitOfWork.CommitAsync(CancellationToken);
        }

        await using (IRegistryUnitOfWork read = await database.UnitOfWorkFactory.BeginAsync(CancellationToken))
        {
            Assert.Equal(activation, await read.Plugins.GetActivationAsync(activation.PluginId, CancellationToken));
        }

        await using (IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken))
        {
            await unitOfWork.Plugins.ClearActivationAsync(activation.PluginId, CancellationToken);
            await unitOfWork.CommitAsync(CancellationToken);
        }

        await using IRegistryUnitOfWork afterClear = await database.UnitOfWorkFactory.BeginAsync(CancellationToken);
        Assert.Null(await afterClear.Plugins.GetActivationAsync(activation.PluginId, CancellationToken));
    }

    private static PluginVersionRecord NewVersion() => new()
    {
        PluginId = "monthly-report",
        Version = new Version(1, 2, 0),
        ContractVersion = "1.0",
        EntryAssembly = "MonthlyReport.dll",
        EntryType = "MonthlyReport.Plugin",
        ExecutionMode = ExecutionMode.InProcess,
        ArtifactHash = "sha256:abc123",
        State = PluginLifecycleState.Uploaded,
        InstalledAt = InstalledAt,
    };
}

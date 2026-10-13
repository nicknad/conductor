using Scheduler.Application.Observability;
using Scheduler.Application.Persistence;
using Scheduler.Application.Secrets;
using Scheduler.Contracts.Secrets;
using Scheduler.Tests.Integration;
using Scheduler.Tests.Support;

namespace Scheduler.Tests.Integration.Secrets;

public sealed class SecretRotationTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task IdleRotationIsPickedUpByTheNextExecution()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(Ct);
        FakeSecretValueStore store = new();
        await store.SetAsync("rotating", "value-v1", Ct);
        await GrantAsync(database, "test-plugin", "test-job", "rotating");

        ISecretProvider firstExecution = await CreateProviderAsync(database, store);
        Assert.Equal("value-v1", await firstExecution.ResolveAsync("rotating", Ct));

        await store.SetAsync("rotating", "value-v2", Ct);

        ISecretProvider nextExecution = await CreateProviderAsync(database, store);
        Assert.Equal("value-v2", await nextExecution.ResolveAsync("rotating", Ct));
    }

    [Fact]
    public async Task RotationDuringARunningExecutionDoesNotChangeItsHeldValue()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(Ct);
        FakeSecretValueStore store = new();
        await store.SetAsync("rotating", "value-v1", Ct);
        await GrantAsync(database, "test-plugin", "test-job", "rotating");

        ISecretProvider running = await CreateProviderAsync(database, store);
        Assert.Equal("value-v1", await running.ResolveAsync("rotating", Ct));

        await store.SetAsync("rotating", "value-v2", Ct);

        // The same execution keeps the value it acquired.
        Assert.Equal("value-v1", await running.ResolveAsync("rotating", Ct));
    }

    private static async Task<ISecretProvider> CreateProviderAsync(SqliteTestDatabase database, FakeSecretValueStore store)
    {
        AuditWriter audit = new(database.UnitOfWorkFactory, TimeProvider.System);
        RegistrySecretProviderFactory factory = new(database.UnitOfWorkFactory, store, audit);
        return await factory.CreateAsync(
            new ExecutionIdentity(Guid.NewGuid(), "corr", "test-job", "test-plugin", new Version(1, 0, 0)),
            Ct);
    }

    private static async Task GrantAsync(SqliteTestDatabase database, string pluginId, string jobId, string reference)
    {
        await using IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(Ct);
        await unitOfWork.SecretGrants.GrantAsync(
            new SecretGrant
            {
                PluginId = pluginId,
                JobId = jobId,
                SecretReference = reference,
                GrantedBy = "test",
                GrantedAt = DateTimeOffset.UtcNow,
            },
            Ct);
        await unitOfWork.CommitAsync(Ct);
    }
}

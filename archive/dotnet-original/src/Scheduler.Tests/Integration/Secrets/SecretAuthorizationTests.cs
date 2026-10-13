using Scheduler.Application.Observability;
using Scheduler.Application.Persistence;
using Scheduler.Application.Secrets;
using Scheduler.Contracts.Secrets;
using Scheduler.Tests.Integration;
using Scheduler.Tests.Support;

namespace Scheduler.Tests.Integration.Secrets;

public sealed class SecretAuthorizationTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task UngrantedReferenceIsDeniedAndAuditedWithoutTheValue()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(Ct);
        FakeSecretValueStore store = new();
        await store.SetAsync("ungranted-ref", "super-secret-value", Ct);
        await store.SetAsync("granted-ref", "allowed-value", Ct);
        await GrantAsync(database, "test-plugin", "test-job", "granted-ref");

        ISecretProvider provider = await CreateProviderAsync(database, store, "test-plugin", "test-job");

        await Assert.ThrowsAsync<SecretNotAuthorizedException>(
            () => provider.ResolveAsync("ungranted-ref", Ct));
        Assert.Equal("allowed-value", await provider.ResolveAsync("granted-ref", Ct));

        IReadOnlyList<AuditEntry> entries = await ReadAuditAsync(database);
        Assert.Contains(entries, entry => entry.Action == "secret.access.denied" && entry.Target == "ungranted-ref");
        Assert.Contains(entries, entry => entry.Action == "secret.access.allowed" && entry.Target == "granted-ref");
        Assert.DoesNotContain(entries, entry => Details(entry).Contains("super-secret-value", StringComparison.Ordinal));
        Assert.DoesNotContain(entries, entry => Details(entry).Contains("allowed-value", StringComparison.Ordinal));
    }

    [Fact]
    public async Task GrantAndRevokeChangeResolutionBehavior()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(Ct);
        FakeSecretValueStore store = new();
        await store.SetAsync("db-password", "value-1", Ct);
        AuditWriter audit = new(database.UnitOfWorkFactory, TimeProvider.System);
        SecretAdminService admin = new(database.UnitOfWorkFactory, store, audit, TimeProvider.System);

        RegistrySecretProviderFactory factory = new(database.UnitOfWorkFactory, store, audit);

        ISecretProvider before = await factory.CreateAsync(Identity("test-plugin", "test-job"), Ct);
        await Assert.ThrowsAsync<SecretNotAuthorizedException>(() => before.ResolveAsync("db-password", Ct));

        await admin.GrantAsync("test-plugin", "test-job", "db-password", "admin", Ct);

        ISecretProvider afterGrant = await factory.CreateAsync(Identity("test-plugin", "test-job"), Ct);
        Assert.Equal("value-1", await afterGrant.ResolveAsync("db-password", Ct));

        Assert.True(await admin.RevokeAsync("test-plugin", "test-job", "db-password", "admin", Ct));

        ISecretProvider afterRevoke = await factory.CreateAsync(Identity("test-plugin", "test-job"), Ct);
        await Assert.ThrowsAsync<SecretNotAuthorizedException>(() => afterRevoke.ResolveAsync("db-password", Ct));
    }

    [Fact]
    public async Task JobScopedGrantOnlyAppliesToThatJob()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(Ct);
        FakeSecretValueStore store = new();
        await store.SetAsync("scoped", "scoped-value", Ct);
        await GrantAsync(database, "test-plugin", "job-a", "scoped");

        ISecretProvider forJobA = await CreateProviderAsync(database, store, "test-plugin", "job-a");
        Assert.Equal("scoped-value", await forJobA.ResolveAsync("scoped", Ct));

        ISecretProvider forJobB = await CreateProviderAsync(database, store, "test-plugin", "job-b");
        await Assert.ThrowsAsync<SecretNotAuthorizedException>(() => forJobB.ResolveAsync("scoped", Ct));
    }

    [Fact]
    public async Task PluginWideGrantAppliesToEveryJob()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(Ct);
        FakeSecretValueStore store = new();
        await store.SetAsync("shared", "shared-value", Ct);
        await GrantAsync(database, "test-plugin", jobId: null, "shared");

        ISecretProvider provider = await CreateProviderAsync(database, store, "test-plugin", "any-job");
        Assert.Equal("shared-value", await provider.ResolveAsync("shared", Ct));
    }

    [Fact]
    public async Task GrantedButMissingValueIsDeniedWithoutFabricatingAValue()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(Ct);
        FakeSecretValueStore store = new();
        await GrantAsync(database, "test-plugin", "test-job", "absent-ref");

        ISecretProvider provider = await CreateProviderAsync(database, store, "test-plugin", "test-job");

        await Assert.ThrowsAsync<SecretNotAuthorizedException>(() => provider.ResolveAsync("absent-ref", Ct));
        IReadOnlyList<AuditEntry> entries = await ReadAuditAsync(database);
        Assert.Contains(entries, entry => entry.Action == "secret.access.denied" && entry.Target == "absent-ref");
    }

    [Fact]
    public async Task AdminOperationsAreAuditedWithoutValues()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(Ct);
        FakeSecretValueStore store = new();
        AuditWriter audit = new(database.UnitOfWorkFactory, TimeProvider.System);
        SecretAdminService admin = new(database.UnitOfWorkFactory, store, audit, TimeProvider.System);

        await admin.SetValueAsync("db-password", "s3cr3t-value", "admin", Ct);
        await admin.GrantAsync("test-plugin", "test-job", "db-password", "admin", Ct);
        Assert.True(await admin.RevokeAsync("test-plugin", "test-job", "db-password", "admin", Ct));
        await admin.RemoveValueAsync("db-password", "admin", Ct);

        IReadOnlyList<AuditEntry> entries = await ReadAuditAsync(database);
        Assert.Contains(entries, entry => entry.Action == "secret.set" && entry.Target == "db-password");
        Assert.Contains(entries, entry => entry.Action == "secret.grant" && entry.Target == "db-password");
        Assert.Contains(entries, entry => entry.Action == "secret.revoke" && entry.Target == "db-password");
        Assert.Contains(entries, entry => entry.Action == "secret.remove" && entry.Target == "db-password");
        Assert.DoesNotContain(entries, entry => Details(entry).Contains("s3cr3t-value", StringComparison.Ordinal));
    }

    private static ExecutionIdentity Identity(string pluginId, string jobId) =>
        new(Guid.NewGuid(), "corr", jobId, pluginId, new Version(1, 0, 0));

    private static async Task<ISecretProvider> CreateProviderAsync(
        SqliteTestDatabase database,
        FakeSecretValueStore store,
        string pluginId,
        string jobId)
    {
        AuditWriter audit = new(database.UnitOfWorkFactory, TimeProvider.System);
        RegistrySecretProviderFactory factory = new(database.UnitOfWorkFactory, store, audit);
        return await factory.CreateAsync(Identity(pluginId, jobId), Ct);
    }

    private static async Task GrantAsync(SqliteTestDatabase database, string pluginId, string? jobId, string reference)
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

    private static async Task<IReadOnlyList<AuditEntry>> ReadAuditAsync(SqliteTestDatabase database)
    {
        await using IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(Ct);
        return await unitOfWork.Audit.ListAsync(100, Ct);
    }

    private static string Details(AuditEntry entry) => entry.Details ?? string.Empty;
}

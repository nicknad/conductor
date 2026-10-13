using Scheduler.Application.Persistence;
using Scheduler.Application.PluginManagement;
using Scheduler.Tests.Support;

namespace Scheduler.Tests.Integration.Packaging;

public sealed class PluginInstallTests
{
    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task InstallsAndPromotesSignedRsaPackage()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using PackagingTestContext context = new(key.PublicKeyPath);
        await context.InitializeAsync(CancellationToken);

        byte[] package = TestPackage.CreateSigned(TestPackage.NewManifest(), TestPackage.DefaultPayload(), key);

        PluginOperation operation = await context.Manager.InstallAsync(new MemoryStream(package), CancellationToken);

        Assert.Equal(PluginOperationStatus.Succeeded, operation.Status);
        Assert.True(await context.ArtifactStore.ExistsAsync("monthly-report", new Version(1, 0, 0), CancellationToken));

        await using IRegistryUnitOfWork unitOfWork = await context.UnitOfWorkFactory.BeginAsync(CancellationToken);
        PluginVersionRecord? record = await unitOfWork.Plugins.GetVersionAsync(
            "monthly-report", new Version(1, 0, 0), CancellationToken);

        Assert.NotNull(record);
        Assert.Equal(PluginLifecycleState.Staged, record.State);
        Assert.NotNull(record.ManifestJson);
        Assert.NotNull(record.ArtifactPath);
        Assert.Null(record.StagingPath);
    }

    [Fact]
    public async Task InstallsAndPromotesSignedEcdsaPackage()
    {
        using TestPackageKey key = TestPackageKey.CreateEcdsa();
        using PackagingTestContext context = new(key.PublicKeyPath);
        await context.InitializeAsync(CancellationToken);

        byte[] package = TestPackage.CreateSigned(TestPackage.NewManifest(), TestPackage.DefaultPayload(), key);

        PluginOperation operation = await context.Manager.InstallAsync(new MemoryStream(package), CancellationToken);

        Assert.Equal(PluginOperationStatus.Succeeded, operation.Status);
    }

    [Fact]
    public async Task ReinstallOfIdenticalContentIsIdempotent()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using PackagingTestContext context = new(key.PublicKeyPath);
        await context.InitializeAsync(CancellationToken);

        byte[] package = TestPackage.CreateSigned(TestPackage.NewManifest(), TestPackage.DefaultPayload(), key);
        await context.Manager.InstallAsync(new MemoryStream(package), CancellationToken);

        PluginOperation second = await context.Manager.InstallAsync(new MemoryStream(package), CancellationToken);

        Assert.Equal(PluginOperationStatus.Succeeded, second.Status);
    }

    [Fact]
    public async Task ListsInstalledPluginVersions()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using PackagingTestContext context = new(key.PublicKeyPath);
        await context.InitializeAsync(CancellationToken);

        byte[] package = TestPackage.CreateSigned(TestPackage.NewManifest(), TestPackage.DefaultPayload(), key);
        await context.Manager.InstallAsync(new MemoryStream(package), CancellationToken);

        IReadOnlyList<PluginDescriptor> plugins = await context.Manager.ListAsync(CancellationToken);
        IReadOnlyList<PluginVersionDescriptor> versions =
            await context.Manager.ListVersionsAsync("monthly-report", CancellationToken);

        PluginDescriptor descriptor = Assert.Single(plugins);
        Assert.Equal("monthly-report", descriptor.PluginId);
        Assert.Null(descriptor.ActiveVersion);
        Assert.Equal(PluginLifecycleState.Staged, descriptor.State);

        PluginVersionDescriptor version = Assert.Single(versions);
        Assert.Equal(new Version(1, 0, 0), version.Version);
        Assert.Equal(PluginLifecycleState.Staged, version.State);
    }
}

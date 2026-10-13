using Scheduler.Application.Persistence;
using Scheduler.Application.PluginManagement;
using Scheduler.Tests.Support;

namespace Scheduler.Tests.Integration.Execution;

public sealed class PluginRuntimeTests
{
    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task LoadsDiscoversAndUnloadsPlugin()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using RuntimeTestContext context = new(key.PublicKeyPath);
        await context.InitializeAsync(CancellationToken);

        Version version = new(1, 0, 0);
        byte[] package = TestPluginPackage.Create(
            "test-plugin",
            "Scheduler.Tests.TestPlugins.TestJobPlugin",
            version,
            key);
        await context.Manager.InstallAsync(new MemoryStream(package), CancellationToken);

        PluginVersionRecord record = (await context.ReadVersionAsync("test-plugin", version, CancellationToken))!;
        LoadedPlugin loaded = await context.Runtime.LoadAsync(
            new PluginLoadRequest("test-plugin", version, record.ArtifactPath!, record.EntryAssembly, record.EntryType),
            CancellationToken);

        Assert.Equal("test-plugin", loaded.PluginId);
        Assert.Single(loaded.Jobs);
        Assert.NotNull(context.Runtime.ResolveHandler("test-job", "test-plugin", version));

        PluginUnloadResult unload = await context.Runtime.UnloadAsync("test-plugin", version, CancellationToken);
        Assert.True(unload.Unloaded, unload.Reason);
        Assert.False(context.Runtime.IsLoaded("test-plugin", version));
    }
}

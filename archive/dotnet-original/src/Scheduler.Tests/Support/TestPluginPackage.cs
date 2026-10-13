using Scheduler.Application.Packaging;

namespace Scheduler.Tests.Support;

/// <summary>
/// Builds a signed package from the compiled <c>Scheduler.Tests.TestPlugins</c>
/// assembly so activation tests load real code through the runtime.
/// </summary>
internal static class TestPluginPackage
{
    private const string EntryAssembly = "Scheduler.Tests.TestPlugins.dll";

    public static byte[] Create(
        string pluginId,
        string entryType,
        Version version,
        TestPackageKey key)
    {
        string assemblyPath = Path.Combine(AppContext.BaseDirectory, EntryAssembly);
        List<(string Path, byte[] Content)> payload =
        [
            (EntryAssembly, File.ReadAllBytes(assemblyPath)),
        ];

        string depsPath = Path.ChangeExtension(assemblyPath, ".deps.json");
        if (File.Exists(depsPath))
        {
            payload.Add((Path.GetFileName(depsPath), File.ReadAllBytes(depsPath)));
        }

        PluginManifest manifest = TestPackage.NewManifest(
            id: pluginId,
            version: version.ToString(),
            entryAssembly: EntryAssembly,
            entryType: entryType);

        return TestPackage.CreateSigned(manifest, payload, key);
    }
}

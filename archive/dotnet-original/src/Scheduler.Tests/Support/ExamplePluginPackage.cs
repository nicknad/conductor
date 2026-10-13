using System.Text;
using Scheduler.Application.Packaging;
using Scheduler.Example.Plugin;

namespace Scheduler.Tests.Support;

/// <summary>
/// Builds signed packages from the compiled example plugin assembly, using the
/// same canonical manifest, digest, and signature pipeline the host validates.
/// </summary>
internal static class ExamplePluginPackage
{
    private const string EntryAssembly = "Scheduler.Example.Plugin.dll";

    private const string EntryType = "Scheduler.Example.Plugin.ReportingPlugin";

    public static byte[] CreateSigned(TestPackageKey key) => CreateSigned(key, ReportingPlugin.PluginVersion);

    public static byte[] CreateSigned(TestPackageKey key, Version version) =>
        TestPackage.CreateSigned(NewManifest(version), ValidPayload(), key);

    /// <summary>Builds an otherwise-valid package whose archive payload does not match its digest.</summary>
    public static byte[] CreateTampered(TestPackageKey key, Version version)
    {
        IReadOnlyList<(string Path, byte[] Content)> tampered =
        [
            (EntryAssembly, Encoding.UTF8.GetBytes("tampered-assembly")),
        ];
        return TestPackage.Create(NewManifest(version), ValidPayload(), tampered, key);
    }

    private static PluginManifest NewManifest(Version version) =>
        TestPackage.NewManifest(
            id: ReportingPlugin.PluginId,
            version: version.ToString(),
            entryAssembly: EntryAssembly,
            entryType: EntryType);

    private static List<(string Path, byte[] Content)> ValidPayload()
    {
        string assemblyPath = Path.Combine(AppContext.BaseDirectory, EntryAssembly);
        List<(string Path, byte[] Content)> payload = [(EntryAssembly, File.ReadAllBytes(assemblyPath))];

        string dependencyPath = Path.ChangeExtension(assemblyPath, ".deps.json");
        if (File.Exists(dependencyPath))
        {
            payload.Add((Path.GetFileName(dependencyPath), File.ReadAllBytes(dependencyPath)));
        }

        return payload;
    }
}

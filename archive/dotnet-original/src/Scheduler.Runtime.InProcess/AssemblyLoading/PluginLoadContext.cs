using System.Reflection;
using System.Runtime.Loader;

namespace Scheduler.Runtime.InProcess.AssemblyLoading;

/// <summary>
/// Collectible load context for one plugin version. Dependencies resolve from
/// the plugin's own package via <see cref="AssemblyDependencyResolver" />; the
/// host's contract assembly is shared so plugins bind to the host's copy.
/// </summary>
/// <remarks>
/// Unloading is cooperative: retained references, running tasks, or callbacks
/// can keep the context alive. Unload failure is an operational condition and
/// must be surfaced, not swallowed.
/// </remarks>
public sealed class PluginLoadContext(
    string pluginId,
    Version pluginVersion,
    string entryAssemblyPath,
    Assembly contractAssembly) : AssemblyLoadContext(
        name: $"plugin:{pluginId}:{pluginVersion}",
        isCollectible: true)
{
    private readonly AssemblyDependencyResolver _resolver = new(entryAssemblyPath);
    private readonly string _contractAssemblyName =
        contractAssembly.GetName().Name ?? throw new ArgumentException("The contract assembly must have a simple name.", nameof(contractAssembly));

    protected override Assembly? Load(AssemblyName assemblyName)
    {
        if (assemblyName.Name == _contractAssemblyName)
        {
            return contractAssembly;
        }

        string? assemblyPath = _resolver.ResolveAssemblyToPath(assemblyName);
        return assemblyPath is not null ? LoadFromAssemblyPath(assemblyPath) : null;
    }

    protected override IntPtr LoadUnmanagedDll(string unmanagedDllName)
    {
        string? libraryPath = _resolver.ResolveUnmanagedDllToPath(unmanagedDllName);
        return libraryPath is not null ? LoadUnmanagedDllFromPath(libraryPath) : IntPtr.Zero;
    }
}

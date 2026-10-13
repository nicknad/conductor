using System.IO.Abstractions;

namespace Scheduler.Infrastructure.Packaging;

/// <summary>Resolves configured packaging paths against the content root.</summary>
internal static class PackagingPaths
{
    public static string Resolve(string path, string? baseDirectory, IFileSystem fileSystem)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(fileSystem);

        if (fileSystem.Path.IsPathRooted(path))
        {
            return fileSystem.Path.GetFullPath(path);
        }

        if (string.IsNullOrEmpty(baseDirectory))
        {
            throw new InvalidOperationException(
                $"Path '{path}' must be rooted when no base directory is configured.");
        }

        return fileSystem.Path.GetFullPath(fileSystem.Path.Combine(baseDirectory, path));
    }

    public static bool IsWithin(string candidate, string root, IFileSystem fileSystem)
    {
        string normalizedCandidate = fileSystem.Path.GetFullPath(candidate);
        string normalizedRoot = fileSystem.Path.GetFullPath(root);
        string prefix = normalizedRoot.EndsWith(fileSystem.Path.DirectorySeparatorChar)
            ? normalizedRoot
            : normalizedRoot + fileSystem.Path.DirectorySeparatorChar;

        return normalizedCandidate.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
            || string.Equals(normalizedCandidate, normalizedRoot, StringComparison.OrdinalIgnoreCase);
    }
}

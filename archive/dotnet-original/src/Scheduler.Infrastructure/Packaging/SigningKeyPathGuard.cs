using System.IO.Abstractions;

namespace Scheduler.Infrastructure.Packaging;

/// <summary>
/// Enforces signing-key hygiene: the public key (and, operationally, its
/// private counterpart) must live outside every writable storage root, so the
/// host can never rewrite the material it trusts.
/// </summary>
public static class SigningKeyPathGuard
{
    /// <exception cref="InvalidOperationException">The key path is missing or inside a writable root.</exception>
    public static void EnsureOutsideWritableRoots(PackagingOptions options, IFileSystem fileSystem)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(fileSystem);

        string keyPath = PackagingPaths.Resolve(options.PublicKeyPath, options.BaseDirectory, fileSystem);
        if (!fileSystem.File.Exists(keyPath))
        {
            throw new InvalidOperationException(
                $"Package signature public key '{keyPath}' does not exist.");
        }

        foreach (string root in options.WritableRoots)
        {
            string resolvedRoot = PackagingPaths.Resolve(root, options.BaseDirectory, fileSystem);
            if (PackagingPaths.IsWithin(keyPath, resolvedRoot, fileSystem))
            {
                throw new InvalidOperationException(
                    $"Package signature public key '{keyPath}' must live outside writable root '{resolvedRoot}'.");
            }
        }
    }
}

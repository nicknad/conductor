using System.IO.Abstractions;
using Scheduler.Infrastructure.Packaging;

namespace Scheduler.Infrastructure.Secrets;

/// <summary>
/// Enforces secret-key hygiene: the store's key file must live outside every
/// writable storage root, so a compromise of the writable area never yields the
/// material that decrypts it.
/// </summary>
public static class SecretKeyPathGuard
{
    /// <exception cref="InvalidOperationException">The key path is inside a writable root.</exception>
    public static void EnsureOutsideWritableRoots(SecretStoreOptions options, IFileSystem fileSystem)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(fileSystem);

        string keyPath = PackagingPaths.Resolve(options.KeyPath, options.BaseDirectory, fileSystem);
        foreach (string root in options.WritableRoots)
        {
            string resolvedRoot = PackagingPaths.Resolve(root, options.BaseDirectory, fileSystem);
            if (PackagingPaths.IsWithin(keyPath, resolvedRoot, fileSystem))
            {
                throw new InvalidOperationException(
                    $"Secret store key '{keyPath}' must live outside writable root '{resolvedRoot}'.");
            }
        }
    }
}

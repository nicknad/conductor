using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Scheduler.Application.Packaging;

/// <summary>
/// Computes the canonical package digest (<c>artifactHash</c>): SHA-256 over a
/// deterministic encoding of every archive entry except the manifest and the
/// signature, ordered by ordinal path. The manifest carries the digest, so it
/// cannot be covered by it; the signature is added last. Archive encoding and
/// compression do not affect the result.
/// </summary>
public static class CanonicalPackageDigest
{
    public const string Prefix = "sha256:";

    public static byte[] ComputeHash(IEnumerable<PackageEntry> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);

        PackageEntry[] included = entries
            .Where(entry => !IsExcluded(entry.Path))
            .OrderBy(entry => entry.Path, StringComparer.Ordinal)
            .ToArray();

        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (PackageEntry entry in included)
        {
            Append(hash, entry);
        }

        return hash.GetHashAndReset();
    }

    public static string Format(byte[] hash)
    {
        ArgumentNullException.ThrowIfNull(hash);
        return Prefix + Convert.ToHexStringLower(hash);
    }

    private static bool IsExcluded(string path) =>
        string.Equals(path, PackageLayout.ManifestFileName, StringComparison.Ordinal)
        || string.Equals(path, PackageLayout.SignatureFileName, StringComparison.Ordinal);

    private static void Append(IncrementalHash hash, PackageEntry entry)
    {
        hash.AppendData(Encoding.UTF8.GetBytes(entry.Path));
        hash.AppendData([0]);
        hash.AppendData(Encoding.UTF8.GetBytes(entry.Length.ToString(CultureInfo.InvariantCulture)));
        hash.AppendData([0]);
        hash.AppendData(Encoding.UTF8.GetBytes(entry.ContentHash));
        hash.AppendData([(byte)'\n']);
    }
}

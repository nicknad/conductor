using Scheduler.Application.Packaging;

namespace Scheduler.Tests.Unit.Packaging;

public sealed class CanonicalPackageDigestTests
{
    private static readonly PackageEntry First = new("a.dll", 3, "aa00");
    private static readonly PackageEntry Second = new("b/inner.dll", 5, "bb11");

    [Fact]
    public void IsOrderIndependent()
    {
        byte[] forward = CanonicalPackageDigest.ComputeHash([First, Second]);
        byte[] reversed = CanonicalPackageDigest.ComputeHash([Second, First]);

        Assert.Equal(forward, reversed);
    }

    [Fact]
    public void ExcludesManifestAndSignature()
    {
        PackageEntry[] entries =
        [
            First,
            Second,
        ];

        PackageEntry manifest = new(PackageLayout.ManifestFileName, 10, "cc22");
        PackageEntry signature = new(PackageLayout.SignatureFileName, 4, "dd33");

        Assert.Equal(
            CanonicalPackageDigest.ComputeHash(entries),
            CanonicalPackageDigest.ComputeHash([.. entries, manifest, signature]));
    }

    [Fact]
    public void ChangesWhenContentChanges()
    {
        byte[] original = CanonicalPackageDigest.ComputeHash([First]);
        byte[] changed = CanonicalPackageDigest.ComputeHash([First with { ContentHash = "ff99" }]);

        Assert.NotEqual(original, changed);
    }

    [Fact]
    public void FormatUsesSha256PrefixAndLowercaseHex()
    {
        string formatted = CanonicalPackageDigest.Format(CanonicalPackageDigest.ComputeHash([First]));

        Assert.StartsWith("sha256:", formatted, StringComparison.Ordinal);
        Assert.Equal(7 + 64, formatted.Length);
        Assert.Equal(formatted.ToLowerInvariant(), formatted);
    }
}

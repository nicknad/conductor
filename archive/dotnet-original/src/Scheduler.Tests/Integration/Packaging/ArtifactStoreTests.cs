using System.Security.Cryptography;
using System.Text;
using Scheduler.Application.Packaging;
using Scheduler.Tests.Support;

namespace Scheduler.Tests.Integration.Packaging;

public sealed class ArtifactStoreTests
{
    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task PromotesStagingIntoImmutableArtifact()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using PackagingTestContext context = new(key.PublicKeyPath);
        await context.InitializeAsync(CancellationToken);

        string staging = await context.ArtifactStore.CreateStagingDirectoryAsync(Guid.NewGuid(), CancellationToken);
        await WriteFileAsync(context, staging, "MonthlyReport.dll", "assembly");
        await WriteFileAsync(context, staging, PackageLayout.ManifestFileName, "{}");
        string hash = HashOf(context, staging, ("MonthlyReport.dll", "assembly"), (PackageLayout.ManifestFileName, "{}"));

        StagedArtifact staged = await context.ArtifactStore.PromoteAsync(
            "monthly-report", new Version(1, 0, 0), staging, hash, CancellationToken);

        Assert.True(await context.ArtifactStore.ExistsAsync("monthly-report", new Version(1, 0, 0), CancellationToken));
        Assert.False(context.FileSystem.Directory.Exists(staging));

        ExtractedPackage? opened = await context.ArtifactStore.OpenAsync("monthly-report", new Version(1, 0, 0), CancellationToken);
        Assert.NotNull(opened);
        Assert.NotNull(opened.ManifestBytes);
        Assert.Equal(2, opened.Entries.Count);
        Assert.Equal(staged.ArtifactPath, opened.ExtractionRoot);
    }

    [Fact]
    public async Task PromotesIdenticalContentIdempotently()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using PackagingTestContext context = new(key.PublicKeyPath);
        await context.InitializeAsync(CancellationToken);

        string first = await StageAsync(context, "assembly");
        string hash = HashOf(context, first, ("MonthlyReport.dll", "assembly"));
        await context.ArtifactStore.PromoteAsync("p", new Version(1, 0, 0), first, hash, CancellationToken);

        string second = await StageAsync(context, "assembly");
        StagedArtifact staged = await context.ArtifactStore.PromoteAsync("p", new Version(1, 0, 0), second, hash, CancellationToken);

        Assert.True(context.FileSystem.Directory.Exists(staged.ArtifactPath));
    }

    [Fact]
    public async Task RejectsDifferentContentAtSameIdentity()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using PackagingTestContext context = new(key.PublicKeyPath);
        await context.InitializeAsync(CancellationToken);

        string first = await StageAsync(context, "assembly");
        string hash = HashOf(context, first, ("MonthlyReport.dll", "assembly"));
        await context.ArtifactStore.PromoteAsync("p", new Version(1, 0, 0), first, hash, CancellationToken);

        string second = await StageAsync(context, "different");
        string conflictingHash = "sha256:" + new string('0', 64);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            context.ArtifactStore.PromoteAsync("p", new Version(1, 0, 0), second, conflictingHash, CancellationToken));
    }

    [Fact]
    public async Task ClearStagingRemovesResidue()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using PackagingTestContext context = new(key.PublicKeyPath);
        await context.InitializeAsync(CancellationToken);

        _ = await context.ArtifactStore.CreateStagingDirectoryAsync(Guid.NewGuid(), CancellationToken);
        _ = await context.ArtifactStore.CreateStagingDirectoryAsync(Guid.NewGuid(), CancellationToken);

        await context.ArtifactStore.ClearStagingAsync(CancellationToken);

        Assert.Empty(context.FileSystem.Directory.GetDirectories(context.Options.StagingRoot));
    }

    private static async Task<string> StageAsync(PackagingTestContext context, string content)
    {
        string staging = await context.ArtifactStore.CreateStagingDirectoryAsync(Guid.NewGuid(), CancellationToken);
        await WriteFileAsync(context, staging, "MonthlyReport.dll", content);
        return staging;
    }

    private static async Task WriteFileAsync(PackagingTestContext context, string directory, string name, string content)
    {
        await context.FileSystem.File.WriteAllTextAsync(
            context.FileSystem.Path.Combine(directory, name),
            content,
            CancellationToken);
    }

    private static string HashOf(
        PackagingTestContext context,
        string directory,
        params (string Name, string Content)[] files)
    {
        PackageEntry[] entries = files
            .Select(file =>
            {
                byte[] bytes = Encoding.UTF8.GetBytes(file.Content);
                return new PackageEntry(file.Name, bytes.Length, Convert.ToHexStringLower(SHA256.HashData(bytes)));
            })
            .ToArray();

        Assert.True(context.FileSystem.Directory.Exists(directory));
        return CanonicalPackageDigest.Format(CanonicalPackageDigest.ComputeHash(entries));
    }
}

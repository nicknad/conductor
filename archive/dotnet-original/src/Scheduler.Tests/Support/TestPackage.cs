using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Scheduler.Application.Packaging;
using Scheduler.Contracts.Execution;

namespace Scheduler.Tests.Support;

/// <summary>
/// Builds plugin packages for tests: computes the canonical digest, produces the
/// canonical manifest, signs it, and packs everything into a ZIP. Tests use the
/// same canonicalization the host verifies against.
/// </summary>
internal static class TestPackage
{
    public static PluginManifest NewManifest(
        string id = "monthly-report",
        string version = "1.0.0",
        string contractVersion = "1.0",
        string entryAssembly = "MonthlyReport.dll",
        string entryType = "MonthlyReport.Plugin",
        ExecutionMode executionMode = ExecutionMode.InProcess) => new()
        {
            Id = id,
            Version = Version.Parse(version),
            ContractVersion = Version.Parse(contractVersion),
            EntryAssembly = entryAssembly,
            EntryType = entryType,
            ExecutionMode = executionMode,
            Capabilities = ["logging"],
            Dependencies = [],
            ArtifactHash = string.Empty,
        };

    public static IReadOnlyList<(string Path, byte[] Content)> DefaultPayload() =>
    [
        ("MonthlyReport.dll", Encoding.UTF8.GetBytes("fake-assembly-bytes")),
        ("MonthlyReport.deps.json", Encoding.UTF8.GetBytes("{}")),
    ];

    public static byte[] CreateSigned(
        PluginManifest manifest,
        IReadOnlyList<(string Path, byte[] Content)> payload,
        TestPackageKey key) =>
        Create(manifest, digestPayload: payload, writePayload: payload, key);

    /// <summary>
    /// Builds a package whose digest and signature are computed over
    /// <paramref name="digestPayload" /> but whose archive contains
    /// <paramref name="writePayload" /> — used to simulate tampered content.
    /// </summary>
    public static byte[] Create(
        PluginManifest manifest,
        IReadOnlyList<(string Path, byte[] Content)> digestPayload,
        IReadOnlyList<(string Path, byte[] Content)> writePayload,
        TestPackageKey key)
    {
        byte[] digest = CanonicalPackageDigest.ComputeHash(Entries(digestPayload));
        PluginManifest signed = manifest with { ArtifactHash = CanonicalPackageDigest.Format(digest) };
        byte[] canonical = PluginManifestJson.ToCanonicalUtf8(signed);
        byte[] signature = key.Sign([.. canonical, .. digest]);
        string signatureJson = JsonSerializer.Serialize(new
        {
            formatVersion = 1,
            algorithm = key.Algorithm,
            signature = Convert.ToBase64String(signature),
        });

        return Zip(
            [.. writePayload,
                (PackageLayout.ManifestFileName, canonical),
                (PackageLayout.SignatureFileName, Encoding.UTF8.GetBytes(signatureJson))]);
    }

    public static byte[] CreateUnsigned(
        PluginManifest manifest,
        IReadOnlyList<(string Path, byte[] Content)> payload)
    {
        PluginManifest withHash = manifest with { ArtifactHash = CanonicalPackageDigest.Format(CanonicalPackageDigest.ComputeHash(Entries(payload))) };
        byte[] canonical = PluginManifestJson.ToCanonicalUtf8(withHash);
        return Zip([.. payload, (PackageLayout.ManifestFileName, canonical)]);
    }

    public static byte[] Zip(IReadOnlyList<(string Path, byte[] Content)> entries)
    {
        using MemoryStream stream = new();
        using (ZipArchive archive = new(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach ((string path, byte[] content) in entries)
            {
                ZipArchiveEntry entry = archive.CreateEntry(path, CompressionLevel.Optimal);
                using Stream target = entry.Open();
                target.Write(content);
            }
        }

        return stream.ToArray();
    }

    public static IReadOnlyList<PackageEntry> Entries(IReadOnlyList<(string Path, byte[] Content)> files) =>
        files
            .Select(file => new PackageEntry(
                file.Path,
                file.Content.Length,
                Convert.ToHexStringLower(SHA256.HashData(file.Content))))
            .ToArray();
}

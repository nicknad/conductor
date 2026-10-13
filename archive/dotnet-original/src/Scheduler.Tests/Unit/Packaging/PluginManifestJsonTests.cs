using System.Text;
using System.Text.Json;
using Scheduler.Application.Packaging;
using Scheduler.Contracts.Execution;

namespace Scheduler.Tests.Unit.Packaging;

public sealed class PluginManifestJsonTests
{
    private static readonly string ValidHash = "sha256:" + new string('a', 64);

    private static readonly string[] CanonicalKeys =
    [
        "artifactHash",
        "capabilities",
        "contractVersion",
        "dependencies",
        "entryAssembly",
        "entryType",
        "executionMode",
        "id",
        "version",
    ];

    [Fact]
    public void CanonicalFormIsDeterministicAndRoundTrips()
    {
        PluginManifest manifest = NewManifest();

        byte[] first = PluginManifestJson.ToCanonicalUtf8(manifest);
        byte[] second = PluginManifestJson.ToCanonicalUtf8(manifest);

        Assert.Equal(first, second);

        PluginManifestParseResult parsed = PluginManifestJson.Parse(first);
        Assert.True(parsed.IsValid);
        PluginManifest reloaded = parsed.Manifest!;

        Assert.Equal(manifest.Id, reloaded.Id);
        Assert.Equal(manifest.Version, reloaded.Version);
        Assert.Equal(manifest.ContractVersion, reloaded.ContractVersion);
        Assert.Equal(manifest.EntryAssembly, reloaded.EntryAssembly);
        Assert.Equal(manifest.EntryType, reloaded.EntryType);
        Assert.Equal(manifest.ExecutionMode, reloaded.ExecutionMode);
        Assert.Equal(manifest.ArtifactHash, reloaded.ArtifactHash);
        Assert.Equal(manifest.Capabilities, reloaded.Capabilities);
        Assert.Equal(manifest.Dependencies, reloaded.Dependencies);
    }

    [Fact]
    public void CanonicalKeysAreOrdinalSorted()
    {
        byte[] canonical = PluginManifestJson.ToCanonicalUtf8(NewManifest());

        using JsonDocument document = JsonDocument.Parse(canonical);
        string[] keys = document.RootElement.EnumerateObject().Select(property => property.Name).ToArray();

        Assert.Equal(CanonicalKeys, keys);
    }

    [Fact]
    public void ParseRejectsMissingRequiredFields()
    {
        PluginManifestParseResult result = PluginManifestJson.Parse(Encoding.UTF8.GetBytes("{}"));

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error => error.Contains("id", StringComparison.Ordinal));
        Assert.Contains(result.Errors, error => error.Contains("artifactHash", StringComparison.Ordinal));
    }

    [Fact]
    public void ParseRejectsInvalidJson()
    {
        PluginManifestParseResult result = PluginManifestJson.Parse(Encoding.UTF8.GetBytes("not-json"));

        Assert.False(result.IsValid);
    }

    [Fact]
    public void ParseRejectsBadVersion()
    {
        string json = ValidJson().Replace("\"version\":\"1.0.0\"", "\"version\":\"abc\"");

        PluginManifestParseResult result = PluginManifestJson.Parse(Encoding.UTF8.GetBytes(json));

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error => error.Contains("version", StringComparison.Ordinal));
    }

    [Fact]
    public void ParseRejectsUnknownExecutionMode()
    {
        string json = ValidJson().Replace("\"executionMode\":\"in-process\"", "\"executionMode\":\"sandbox\"");

        PluginManifestParseResult result = PluginManifestJson.Parse(Encoding.UTF8.GetBytes(json));

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error => error.Contains("executionMode", StringComparison.Ordinal));
    }

    [Fact]
    public void ParseRejectsMalformedArtifactHash()
    {
        string json = ValidJson().Replace(ValidHash, "sha256:xyz");

        PluginManifestParseResult result = PluginManifestJson.Parse(Encoding.UTF8.GetBytes(json));

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error => error.Contains("artifactHash", StringComparison.Ordinal));
    }

    [Fact]
    public void ParseTreatsCapabilitiesAndDependenciesAsOptional()
    {
        string json =
            """
            {"id":"p","version":"1.0.0","contractVersion":"1.0","entryAssembly":"a.dll",
             "entryType":"T","executionMode":"worker","artifactHash":"sha256:HASH"}
            """.Replace("HASH", new string('b', 64));

        PluginManifestParseResult result = PluginManifestJson.Parse(Encoding.UTF8.GetBytes(json));

        Assert.True(result.IsValid);
        Assert.Empty(result.Manifest!.Capabilities);
        Assert.Empty(result.Manifest.Dependencies);
        Assert.Equal(ExecutionMode.Worker, result.Manifest.ExecutionMode);
    }

    private static string ValidJson() =>
        $$"""
        {"id":"monthly-report","version":"1.0.0","contractVersion":"1.0",
         "entryAssembly":"MonthlyReport.dll","entryType":"MonthlyReport.Plugin",
         "executionMode":"in-process","capabilities":["logging"],"dependencies":[],
         "artifactHash":"{{ValidHash}}"}
        """;

    private static PluginManifest NewManifest() => new()
    {
        Id = "monthly-report",
        Version = new Version(1, 0, 0),
        ContractVersion = new Version(1, 0),
        EntryAssembly = "MonthlyReport.dll",
        EntryType = "MonthlyReport.Plugin",
        ExecutionMode = ExecutionMode.InProcess,
        Capabilities = ["logging"],
        Dependencies = ["Some.Dependency"],
        ArtifactHash = ValidHash,
    };
}

using Scheduler.Contracts.Execution;

namespace Scheduler.Application.Packaging;

/// <summary>
/// Canonical, validated shape of a package's <c>plugin.json</c>. The signature is
/// not part of the manifest; it is carried separately by <c>signature.json</c>.
/// See <see href="docs/02-plugin-package.md" />.
/// </summary>
public sealed record PluginManifest
{
    public required string Id { get; init; }

    public required Version Version { get; init; }

    public required Version ContractVersion { get; init; }

    public required string EntryAssembly { get; init; }

    public required string EntryType { get; init; }

    public required ExecutionMode ExecutionMode { get; init; }

    public IReadOnlyList<string> Capabilities { get; init; } = [];

    public IReadOnlyList<string> Dependencies { get; init; } = [];

    /// <summary>Canonical package digest, formatted as <c>sha256:&lt;hex&gt;</c>.</summary>
    public required string ArtifactHash { get; init; }
}

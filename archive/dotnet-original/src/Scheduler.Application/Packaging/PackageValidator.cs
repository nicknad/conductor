namespace Scheduler.Application.Packaging;

/// <summary>Outcome of validating a package against every gate.</summary>
public sealed record PackageValidationResult(
    PluginManifest? Manifest,
    bool IsValid,
    IReadOnlyList<string> Errors,
    IReadOnlyList<string> Warnings);

/// <summary>
/// Runs the manifest, digest, signature, and assembly-level gates over an
/// already-safely-extracted package. Archive safety is enforced during
/// extraction. All applicable gates are evaluated so the report is complete.
/// </summary>
public sealed class PackageValidator
{
    private readonly IPackageSignatureVerifier _signatureVerifier;

    public PackageValidator(IPackageSignatureVerifier signatureVerifier)
    {
        ArgumentNullException.ThrowIfNull(signatureVerifier);
        _signatureVerifier = signatureVerifier;
    }

    public PackageValidationResult Validate(ExtractedPackage package, Version hostContractVersion)
    {
        ArgumentNullException.ThrowIfNull(package);
        ArgumentNullException.ThrowIfNull(hostContractVersion);

        List<string> errors = [];

        if (package.ManifestBytes is null)
        {
            return new PackageValidationResult(
                Manifest: null,
                IsValid: false,
                Errors: [$"Package is missing '{PackageLayout.ManifestFileName}'."],
                Warnings: []);
        }

        PluginManifestParseResult parsed = PluginManifestJson.Parse(package.ManifestBytes);
        if (!parsed.IsValid)
        {
            return new PackageValidationResult(
                Manifest: null,
                IsValid: false,
                Errors: parsed.Errors,
                Warnings: []);
        }

        PluginManifest manifest = parsed.Manifest!;

        if (!ContractCompatibility.IsCompatible(hostContractVersion, manifest.ContractVersion))
        {
            errors.Add(ContractCompatibility.Describe(hostContractVersion, manifest.ContractVersion));
        }

        byte[] digest = CanonicalPackageDigest.ComputeHash(package.Entries);
        string actualHash = CanonicalPackageDigest.Format(digest);
        if (!string.Equals(actualHash, manifest.ArtifactHash, StringComparison.Ordinal))
        {
            errors.Add(
                $"Package digest '{actualHash}' does not match manifest artifactHash '{manifest.ArtifactHash}'.");
        }

        ValidateSignature(package, manifest, digest, errors);

        if (!HasEntry(package.Entries, manifest.EntryAssembly))
        {
            errors.Add($"Entry assembly '{manifest.EntryAssembly}' is not present in the package.");
        }

        return new PackageValidationResult(manifest, errors.Count == 0, errors, []);
    }

    private void ValidateSignature(
        ExtractedPackage package,
        PluginManifest manifest,
        byte[] digest,
        List<string> errors)
    {
        if (package.SignatureBytes is null)
        {
            errors.Add($"Package is missing '{PackageLayout.SignatureFileName}'.");
            return;
        }

        PackageSignatureParseResult parsed = PackageSignatureJson.Parse(package.SignatureBytes);
        if (!parsed.IsValid)
        {
            errors.AddRange(parsed.Errors);
            return;
        }

        byte[] canonicalManifest = PluginManifestJson.ToCanonicalUtf8(manifest);
        PackageSignatureVerificationResult verification =
            _signatureVerifier.Verify(canonicalManifest, digest, parsed.Signature!);
        if (!verification.IsValid)
        {
            errors.Add($"Package signature is invalid: {verification.Reason}");
        }
    }

    private static bool HasEntry(IReadOnlyList<PackageEntry> entries, string entryAssembly)
    {
        string normalized = entryAssembly.Replace('\\', '/');
        return entries.Any(entry => string.Equals(entry.Path, normalized, StringComparison.OrdinalIgnoreCase));
    }
}

namespace Scheduler.Application.Packaging;

/// <summary>Verifies a detached package signature against the platform public key.</summary>
public interface IPackageSignatureVerifier
{
    /// <summary>
    /// Verifies <paramref name="signature" /> over the canonical manifest bytes
    /// followed by the raw package digest. Never throws for a bad signature; it
    /// returns an invalid result with a sanitized reason.
    /// </summary>
    PackageSignatureVerificationResult Verify(
        ReadOnlySpan<byte> canonicalManifest,
        ReadOnlySpan<byte> packageDigest,
        PackageSignature signature);
}

/// <summary>Outcome of signature verification.</summary>
public sealed record PackageSignatureVerificationResult(bool IsValid, string? Reason)
{
    public static PackageSignatureVerificationResult Valid() => new(true, null);

    public static PackageSignatureVerificationResult Invalid(string reason) => new(false, reason);
}

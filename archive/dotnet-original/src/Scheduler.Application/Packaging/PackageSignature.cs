namespace Scheduler.Application.Packaging;

/// <summary>Signature algorithm supported by package verification.</summary>
public enum PackageSignatureAlgorithm
{
    /// <summary>RSA PKCS#1 v1.5 over SHA-256.</summary>
    Rs256,

    /// <summary>ECDSA P-256 over SHA-256.</summary>
    Es256,
}

/// <summary>
/// Detached signature for a package: it covers the canonical manifest bytes
/// followed by the raw package digest. Serialized as <c>signature.json</c>.
/// </summary>
public sealed record PackageSignature(
    int FormatVersion,
    PackageSignatureAlgorithm Algorithm,
    byte[] Signature);

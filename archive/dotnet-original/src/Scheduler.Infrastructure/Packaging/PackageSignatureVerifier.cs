using System.IO.Abstractions;
using System.Security.Cryptography;
using Scheduler.Application.Packaging;

namespace Scheduler.Infrastructure.Packaging;

/// <summary>
/// Verifies detached package signatures against the configured PEM public key.
/// The key type (RSA or ECDSA) is detected at construction; the signature's
/// declared algorithm must match it.
/// </summary>
public sealed class PackageSignatureVerifier : IPackageSignatureVerifier, IDisposable
{
    private readonly RSA? _rsa;
    private readonly ECDsa? _ecdsa;

    public PackageSignatureVerifier(PackagingOptions options, IFileSystem fileSystem)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(fileSystem);

        string keyPath = PackagingPaths.Resolve(options.PublicKeyPath, options.BaseDirectory, fileSystem);
        string pem = fileSystem.File.ReadAllText(keyPath);

        RSA rsa = RSA.Create();
        if (TryImport(rsa, pem))
        {
            _rsa = rsa;
            return;
        }

        rsa.Dispose();

        ECDsa ecdsa = ECDsa.Create();
        if (TryImport(ecdsa, pem))
        {
            _ecdsa = ecdsa;
            return;
        }

        ecdsa.Dispose();
        throw new InvalidOperationException(
            $"Public key '{keyPath}' is neither a supported RSA nor ECDSA public key.");
    }

    public PackageSignatureVerificationResult Verify(
        ReadOnlySpan<byte> canonicalManifest,
        ReadOnlySpan<byte> packageDigest,
        PackageSignature signature)
    {
        ArgumentNullException.ThrowIfNull(signature);

        byte[] data = new byte[canonicalManifest.Length + packageDigest.Length];
        canonicalManifest.CopyTo(data);
        packageDigest.CopyTo(data.AsSpan(canonicalManifest.Length));

        try
        {
            if (_rsa is not null)
            {
                if (signature.Algorithm != PackageSignatureAlgorithm.Rs256)
                {
                    return PackageSignatureVerificationResult.Invalid(
                        "Signature algorithm does not match the configured RSA key.");
                }

                bool valid = _rsa.VerifyData(
                    data,
                    signature.Signature,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);
                return valid
                    ? PackageSignatureVerificationResult.Valid()
                    : PackageSignatureVerificationResult.Invalid("Signature does not match the manifest.");
            }

            if (signature.Algorithm != PackageSignatureAlgorithm.Es256)
            {
                return PackageSignatureVerificationResult.Invalid(
                    "Signature algorithm does not match the configured ECDSA key.");
            }

            bool ecdsaValid = _ecdsa!.VerifyData(data, signature.Signature, HashAlgorithmName.SHA256);
            return ecdsaValid
                ? PackageSignatureVerificationResult.Valid()
                : PackageSignatureVerificationResult.Invalid("Signature does not match the manifest.");
        }
        catch (CryptographicException)
        {
            return PackageSignatureVerificationResult.Invalid("Signature is malformed.");
        }
    }

    public void Dispose()
    {
        _rsa?.Dispose();
        _ecdsa?.Dispose();
        GC.SuppressFinalize(this);
    }

    private static bool TryImport(AsymmetricAlgorithm algorithm, string pem)
    {
        try
        {
            switch (algorithm)
            {
                case RSA rsa:
                    rsa.ImportFromPem(pem);
                    return true;
                case ECDsa ecdsa:
                    ecdsa.ImportFromPem(pem);
                    return true;
                default:
                    return false;
            }
        }
        catch (Exception exception) when (exception is ArgumentException or CryptographicException)
        {
            return false;
        }
    }
}

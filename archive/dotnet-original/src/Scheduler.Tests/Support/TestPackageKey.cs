using System.Security.Cryptography;

namespace Scheduler.Tests.Support;

/// <summary>
/// A signing key pair for tests. The public half is written to a temp file for
/// the verifier; dummy keys only — never real secrets.
/// </summary>
internal sealed class TestPackageKey : IDisposable
{
    private readonly string _directory;
    private readonly RSA? _rsa;
    private readonly ECDsa? _ecdsa;

    private TestPackageKey(string directory, string algorithm, RSA? rsa, ECDsa? ecdsa)
    {
        _directory = directory;
        Algorithm = algorithm;
        _rsa = rsa;
        _ecdsa = ecdsa;
        PublicKeyPath = Path.Combine(directory, "public.pem");
    }

    public string Algorithm { get; }

    public string PublicKeyPath { get; }

    public static TestPackageKey CreateRsa()
    {
        string directory = NewDirectory();
        RSA rsa = RSA.Create(2048);
        TestPackageKey key = new(directory, "RS256", rsa, null);
        key.WritePublicKey(rsa.ExportSubjectPublicKeyInfoPem());
        return key;
    }

    public static TestPackageKey CreateEcdsa()
    {
        string directory = NewDirectory();
        ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        TestPackageKey key = new(directory, "ES256", null, ecdsa);
        key.WritePublicKey(ecdsa.ExportSubjectPublicKeyInfoPem());
        return key;
    }

    public byte[] Sign(byte[] data) => _rsa is not null
        ? _rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
        : _ecdsa!.SignData(data, HashAlgorithmName.SHA256);

    public void Dispose()
    {
        _rsa?.Dispose();
        _ecdsa?.Dispose();

        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (DirectoryNotFoundException)
        {
        }
        catch (IOException)
        {
        }
    }

    private static string NewDirectory()
    {
        string directory = Path.Combine(Path.GetTempPath(), "jobscheduler-keys", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        return directory;
    }

    private void WritePublicKey(string pem) => File.WriteAllText(PublicKeyPath, pem);
}

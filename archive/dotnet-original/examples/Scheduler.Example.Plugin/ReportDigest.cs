using System.Security.Cryptography;
using System.Text;

namespace Scheduler.Example.Plugin;

/// <summary>
/// Derives a stable, non-reversible fingerprint of a secret value, so the
/// example can prove it used the secret without ever logging or writing the
/// value itself.
/// </summary>
public static class ReportDigest
{
    private const int DigestCharacters = 12;

    public static string OfValue(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexStringLower(hash)[..DigestCharacters];
    }
}

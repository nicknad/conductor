using System.Security.Cryptography;
using System.Text;
using Scheduler.Application.Secrets;
using Scheduler.Application.Security;

namespace Scheduler.Infrastructure.Security;

/// <summary>
/// Authenticates bearer tokens against credentials whose values are resolved
/// from the encrypted store by reference. A configured reference with no stored
/// value is a startup failure; the authenticator never holds a literal token.
/// </summary>
public sealed class SecretBackedApiAuthenticator : IApiAuthenticator
{
    private const string BearerPrefix = "Bearer ";

    private readonly ManagementApiOptions _options;
    private readonly ISecretValueStore _store;
    private readonly Dictionary<string, ApiPrincipal> _credentials = new(StringComparer.Ordinal);

    public SecretBackedApiAuthenticator(ManagementApiOptions options, ISecretValueStore store)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(store);

        _options = options;
        _store = store;
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        _credentials.Clear();
        foreach (ApiCredentialOptions credential in _options.Credentials)
        {
            string token = await _store.GetAsync(credential.Reference, cancellationToken)
                ?? throw new InvalidOperationException(
                    $"Management API credential '{credential.Reference}' is not present in the secret store.");

            if (_credentials.TryGetValue(token, out ApiPrincipal? existing))
            {
                throw new InvalidOperationException(
                    $"Management API credentials '{existing.Name}' and '{credential.Reference}' resolve to the same token value.");
            }

            _credentials[token] = new ApiPrincipal(credential.Reference, Combine(credential.Scopes));
        }
    }

    public bool TryAuthenticate(string? authorizationHeader, out ApiPrincipal principal)
    {
        principal = null!;
        if (string.IsNullOrWhiteSpace(authorizationHeader)
            || !authorizationHeader.StartsWith(BearerPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        string token = authorizationHeader[BearerPrefix.Length..].Trim();
        if (token.Length == 0)
        {
            return false;
        }

        foreach ((string candidate, ApiPrincipal mapped) in _credentials)
        {
            if (FixedTimeEquals(candidate, token))
            {
                principal = mapped;
                return true;
            }
        }

        return false;
    }

    private static AuthorizationScope Combine(IReadOnlyList<AuthorizationScope> scopes)
    {
        AuthorizationScope result = AuthorizationScope.None;
        foreach (AuthorizationScope scope in scopes)
        {
            result |= scope;
        }

        return result;
    }

    private static bool FixedTimeEquals(string left, string right)
    {
        byte[] leftBytes = Encoding.UTF8.GetBytes(left);
        byte[] rightBytes = Encoding.UTF8.GetBytes(right);
        return leftBytes.Length == rightBytes.Length
            && CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
    }
}

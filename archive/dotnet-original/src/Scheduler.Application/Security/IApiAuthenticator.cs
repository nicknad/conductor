namespace Scheduler.Application.Security;

/// <summary>
/// Authenticates management-API bearer tokens against credentials loaded at
/// startup. The token value is resolved from the encrypted store by reference;
/// the authenticator holds only the reference-derived principal and its scopes.
/// </summary>
public interface IApiAuthenticator
{
    /// <summary>Loads every configured credential from the store. A missing value fails startup.</summary>
    Task InitializeAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates an <c>Authorization</c> header value (for example
    /// <c>"Bearer &lt;token&gt;"</c>) and returns the matching principal.
    /// </summary>
    bool TryAuthenticate(string? authorizationHeader, out ApiPrincipal principal);
}

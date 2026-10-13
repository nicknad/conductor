namespace Scheduler.Application.Security;

/// <summary>
/// Management-API authentication configuration. Credentials are named by a
/// secret reference (never a literal value); the referenced value lives in the
/// encrypted store and is loaded at startup. Authentication is on by default.
/// </summary>
public sealed class ManagementApiOptions
{
    public bool Enabled { get; init; } = true;

    /// <summary>When false (default), the API is intended to bind loopback only.</summary>
    public bool AllowRemoteAccess { get; init; }

    public IReadOnlyList<ApiCredentialOptions> Credentials { get; init; } = [];

    /// <summary>
    /// Rejects configurations that would run the API in an unsafe or unusable state:
    /// authentication disabled while remote access is allowed, or the API enabled with
    /// no credentials.
    /// </summary>
    /// <exception cref="InvalidOperationException">The configuration is invalid.</exception>
    public void Validate()
    {
        if (!Enabled && AllowRemoteAccess)
        {
            throw new InvalidOperationException(
                "The management API cannot disable authentication while remote access is enabled.");
        }

        if (Enabled && Credentials.Count == 0)
        {
            throw new InvalidOperationException(
                "The management API is enabled but no credentials are configured. Configure at least one credential reference.");
        }
    }
}

/// <summary>One configured API credential: a secret reference and its scopes.</summary>
public sealed class ApiCredentialOptions
{
    public required string Reference { get; init; }

    public IReadOnlyList<AuthorizationScope> Scopes { get; init; } = [];
}

/// <summary>The authenticated caller: a credential name and its granted scopes.</summary>
public sealed record ApiPrincipal(string Name, AuthorizationScope Scopes)
{
    /// <summary>Whether the principal holds every scope in <paramref name="required" />.</summary>
    public bool Has(AuthorizationScope required) => (Scopes & required) == required;
}

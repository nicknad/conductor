using Scheduler.Application.Security;
using Scheduler.Infrastructure.Security;
using Scheduler.Tests.Support;

namespace Scheduler.Tests.Integration.Security;

public sealed class ApiAuthenticationTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task ValidTokenAuthenticatesWithItsScopes()
    {
        FakeSecretValueStore store = new();
        await store.SetAsync("admin", "token-admin-value", Ct);
        SecretBackedApiAuthenticator authenticator = new(Options("admin", AuthorizationScope.Read, AuthorizationScope.SecretAdmin), store);
        await authenticator.InitializeAsync(Ct);

        Assert.True(authenticator.TryAuthenticate("Bearer token-admin-value", out ApiPrincipal principal));
        Assert.Equal("admin", principal.Name);
        Assert.True(principal.Has(AuthorizationScope.Read));
        Assert.True(principal.Has(AuthorizationScope.SecretAdmin));
        Assert.False(principal.Has(AuthorizationScope.Remove));
    }

    [Fact]
    public async Task MissingOrMalformedTokensAreRejected()
    {
        FakeSecretValueStore store = new();
        await store.SetAsync("admin", "token-admin-value", Ct);
        SecretBackedApiAuthenticator authenticator = new(Options("admin", AuthorizationScope.Read), store);
        await authenticator.InitializeAsync(Ct);

        Assert.False(authenticator.TryAuthenticate(null, out _));
        Assert.False(authenticator.TryAuthenticate(string.Empty, out _));
        Assert.False(authenticator.TryAuthenticate("Basic abc", out _));
        Assert.False(authenticator.TryAuthenticate("Bearer ", out _));
        Assert.False(authenticator.TryAuthenticate("Bearer not-the-token", out _));
    }

    [Fact]
    public async Task MissingReferencedValueFailsStartup()
    {
        FakeSecretValueStore store = new();
        SecretBackedApiAuthenticator authenticator = new(Options("missing", AuthorizationScope.Read), store);

        await Assert.ThrowsAsync<InvalidOperationException>(() => authenticator.InitializeAsync(Ct));
    }

    [Fact]
    public async Task DuplicateResolvedTokensFailStartup()
    {
        FakeSecretValueStore store = new();
        await store.SetAsync("first", "shared-token-value", Ct);
        await store.SetAsync("second", "shared-token-value", Ct);
        ManagementApiOptions options = new()
        {
            Credentials =
            [
                new ApiCredentialOptions { Reference = "first", Scopes = [AuthorizationScope.Read] },
                new ApiCredentialOptions { Reference = "second", Scopes = [AuthorizationScope.Read] },
            ],
        };
        SecretBackedApiAuthenticator authenticator = new(options, store);

        await Assert.ThrowsAsync<InvalidOperationException>(() => authenticator.InitializeAsync(Ct));
    }

    [Fact]
    public void PrincipalRequiresEveryRequestedScope()
    {
        ApiPrincipal principal = new("x", AuthorizationScope.Read | AuthorizationScope.Activate);

        Assert.True(principal.Has(AuthorizationScope.Read));
        Assert.True(principal.Has(AuthorizationScope.Read | AuthorizationScope.Activate));
        Assert.False(principal.Has(AuthorizationScope.Remove));
        Assert.False(principal.Has(AuthorizationScope.Read | AuthorizationScope.Remove));
    }

    [Fact]
    public void LoopbackIsTheDefault()
    {
        ManagementApiOptions options = new();
        Assert.True(options.Enabled);
        Assert.False(options.AllowRemoteAccess);
        Assert.Empty(options.Credentials);
    }

    private static ManagementApiOptions Options(string reference, params AuthorizationScope[] scopes) => new()
    {
        Credentials =
        [
            new ApiCredentialOptions { Reference = reference, Scopes = scopes },
        ],
    };
}

using Scheduler.Application.Security;

namespace Scheduler.Tests.Unit.Security;

public sealed class ManagementApiOptionsTests
{
    [Theory]
    [InlineData("read", AuthorizationScope.Read)]
    [InlineData("manual-run", AuthorizationScope.ManualRun)]
    [InlineData("secret-admin", AuthorizationScope.SecretAdmin)]
    [InlineData("ManualRun", AuthorizationScope.ManualRun)]
    [InlineData("SECRET-ADMIN", AuthorizationScope.SecretAdmin)]
    public void ParsesKebabAndPascalScopeNames(string name, AuthorizationScope expected)
    {
        Assert.True(AuthorizationScopeNames.TryParse(name, out AuthorizationScope scope));
        Assert.Equal(expected, scope);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not-a-scope")]
    public void RejectsUnknownOrEmptyScopeNames(string? name)
    {
        Assert.False(AuthorizationScopeNames.TryParse(name, out _));
    }

    [Fact]
    public void DisabledAuthenticationWithRemoteAccessIsRejected()
    {
        ManagementApiOptions options = new() { Enabled = false, AllowRemoteAccess = true };

        Assert.Throws<InvalidOperationException>(options.Validate);
    }

    [Fact]
    public void EnabledWithoutCredentialsIsRejected()
    {
        ManagementApiOptions options = new() { Enabled = true, Credentials = [] };

        Assert.Throws<InvalidOperationException>(options.Validate);
    }

    [Fact]
    public void DisabledAuthenticationWithLoopbackIsAllowed()
    {
        ManagementApiOptions options = new() { Enabled = false, AllowRemoteAccess = false };

        options.Validate();
    }

    [Fact]
    public void EnabledWithACredentialIsAllowed()
    {
        ManagementApiOptions options = new()
        {
            Credentials = [new ApiCredentialOptions { Reference = "admin", Scopes = [AuthorizationScope.Read] }],
        };

        options.Validate();
    }
}

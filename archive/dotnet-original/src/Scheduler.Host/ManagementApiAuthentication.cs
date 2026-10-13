using Microsoft.Extensions.DependencyInjection;
using Scheduler.Application.Security;

namespace Scheduler.Host;

/// <summary>
/// Authenticates <c>/api</c> requests against the configured credentials and
/// stashes the principal for the endpoint scope filter. Missing or unknown
/// tokens get 401; the read/health-liveness endpoints outside <c>/api</c> are
/// untouched.
/// </summary>
internal sealed class ManagementApiAuthenticationMiddleware
{
    public const string PrincipalKey = "scheduler.principal";

    private readonly RequestDelegate _next;
    private readonly ManagementApiOptions _options;
    private readonly IApiAuthenticator _authenticator;
    private readonly ILogger<ManagementApiAuthenticationMiddleware> _logger;

    public ManagementApiAuthenticationMiddleware(
        RequestDelegate next,
        ManagementApiOptions options,
        IApiAuthenticator authenticator,
        ILogger<ManagementApiAuthenticationMiddleware> logger)
    {
        ArgumentNullException.ThrowIfNull(next);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(authenticator);
        ArgumentNullException.ThrowIfNull(logger);

        _next = next;
        _options = options;
        _authenticator = authenticator;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!context.Request.Path.StartsWithSegments("/api"))
        {
            await _next(context);
            return;
        }

        if (!_options.Enabled)
        {
            context.Items[PrincipalKey] = new ApiPrincipal("anonymous", AuthorizationScope.All);
            await _next(context);
            return;
        }

        if (!_authenticator.TryAuthenticate(context.Request.Headers.Authorization, out ApiPrincipal principal))
        {
            HostLog.AuthenticationRejected(_logger, "unauthenticated");
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsJsonAsync(
                new { error = "A valid bearer token is required.", reason = "unauthenticated" });
            return;
        }

        context.Items[PrincipalKey] = principal;
        await _next(context);
    }

    public static ApiPrincipal? Principal(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return context.Items.TryGetValue(PrincipalKey, out object? value) ? value as ApiPrincipal : null;
    }
}

/// <summary>Requires a specific permission for a management endpoint.</summary>
internal sealed class ScopeRequirementFilter(AuthorizationScope required) : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(
        EndpointFilterInvocationContext context,
        EndpointFilterDelegate next)
    {
        ArgumentNullException.ThrowIfNull(context);

        ApiPrincipal? principal = ManagementApiAuthenticationMiddleware.Principal(context.HttpContext);
        ILogger<ScopeRequirementFilter> logger =
            context.HttpContext.RequestServices.GetRequiredService<ILogger<ScopeRequirementFilter>>();

        if (principal is null)
        {
            HostLog.AuthenticationRejected(logger, "unauthenticated");
            return Results.Json(
                new { error = "Authentication is required.", reason = "unauthenticated" },
                statusCode: StatusCodes.Status401Unauthorized);
        }

        if (!principal.Has(required))
        {
            HostLog.AuthorizationForbidden(logger, required.ToString());
            return Results.Json(
                new { error = $"The '{required}' permission is required.", reason = "forbidden" },
                statusCode: StatusCodes.Status403Forbidden);
        }

        return await next(context);
    }
}

internal static class ManagementApiAuthorizationExtensions
{
    public static RouteHandlerBuilder RequireScope(this RouteHandlerBuilder builder, AuthorizationScope scope) =>
        builder.AddEndpointFilter(new ScopeRequirementFilter(scope));
}

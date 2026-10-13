using Scheduler.Application.Reconciliation;

namespace Scheduler.Host;

/// <summary>
/// Best-effort reconciliation immediately after a lifecycle or job mutation. The
/// durable outbox record is the source of truth, so this only shortens the
/// convergence delay: a failed sweep is retried by the periodic reconciler and
/// never fails the already-committed request.
/// </summary>
internal sealed class ReconcileAfterLifecycleFilter : IEndpointFilter
{
    private readonly IReconciler _reconciler;
    private readonly ILogger<ReconcileAfterLifecycleFilter> _logger;

    public ReconcileAfterLifecycleFilter(
        IReconciler reconciler,
        ILogger<ReconcileAfterLifecycleFilter> logger)
    {
        ArgumentNullException.ThrowIfNull(reconciler);
        ArgumentNullException.ThrowIfNull(logger);

        _reconciler = reconciler;
        _logger = logger;
    }

    public async ValueTask<object?> InvokeAsync(
        EndpointFilterInvocationContext context,
        EndpointFilterDelegate next)
    {
        object? result = await next(context);
        if (!IsSuccessful(result))
        {
            return result;
        }

        try
        {
            await _reconciler.ReconcileAsync(context.HttpContext.RequestAborted);
        }
        catch (Exception exception)
        {
            HostLog.PostLifecycleReconciliationFailed(_logger, exception);
        }

        return result;
    }

    private static bool IsSuccessful(object? result) => result switch
    {
        IStatusCodeHttpResult { StatusCode: >= StatusCodes.Status400BadRequest } => false,
        _ => true,
    };
}

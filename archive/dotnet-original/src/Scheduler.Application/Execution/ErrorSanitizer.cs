namespace Scheduler.Application.Execution;

/// <summary>
/// Produces the short, sanitized failure text persisted on an execution. It
/// never includes exception messages or stack details, which could leak secrets
/// or internal state; full detail belongs in host logs.
/// </summary>
public static class ErrorSanitizer
{
    public static string Sanitize(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);

        return exception switch
        {
            TimeoutException => "Execution timed out.",
            OperationCanceledException => "Execution was cancelled.",
            _ => $"Execution failed ({exception.GetType().Name}).",
        };
    }
}

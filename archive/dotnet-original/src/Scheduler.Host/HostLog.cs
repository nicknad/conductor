namespace Scheduler.Host;

/// <summary>Source-generated log messages for the host composition root.</summary>
internal static partial class HostLog
{
    [LoggerMessage(
        EventId = 1001,
        Level = LogLevel.Error,
        Message = "Post-lifecycle reconciliation failed; the periodic sweep will retry.")]
    public static partial void PostLifecycleReconciliationFailed(ILogger logger, Exception exception);

    [LoggerMessage(
        EventId = 1002,
        Level = LogLevel.Information,
        Message = "Shutdown drain started: {Count} running execution(s), policy {Policy}.")]
    public static partial void ShutdownDrainStarted(ILogger logger, int count, string policy);

    [LoggerMessage(
        EventId = 1003,
        Level = LogLevel.Information,
        Message = "Shutdown drain finished: drained={Drained}, remaining={Remaining}.")]
    public static partial void ShutdownDrainFinished(ILogger logger, bool drained, int remaining);

    [LoggerMessage(
        EventId = 1004,
        Level = LogLevel.Warning,
        Message = "Stuck executions detected: {Count} ({Ids}).")]
    public static partial void StuckExecutionsDetected(ILogger logger, int count, string ids);

    [LoggerMessage(
        EventId = 1005,
        Level = LogLevel.Warning,
        Message = "Management API remote access is enabled. Bearer tokens are otherwise sent in cleartext; terminate TLS in front of the API.")]
    public static partial void RemoteAccessEnabled(ILogger logger);

    [LoggerMessage(
        EventId = 1006,
        Level = LogLevel.Warning,
        Message = "Management API request rejected: {Reason}.")]
    public static partial void AuthenticationRejected(ILogger logger, string reason);

    [LoggerMessage(
        EventId = 1007,
        Level = LogLevel.Warning,
        Message = "Management API request forbidden: {Permission}.")]
    public static partial void AuthorizationForbidden(ILogger logger, string permission);
}

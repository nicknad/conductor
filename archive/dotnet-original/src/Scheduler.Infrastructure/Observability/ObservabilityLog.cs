using Microsoft.Extensions.Logging;

namespace Scheduler.Infrastructure.Observability;

/// <summary>Source-generated log messages for the observability layer.</summary>
internal static partial class ObservabilityLog
{
    [LoggerMessage(EventId = 2001, Level = LogLevel.Trace, Message = "{Message}")]
    public static partial void Trace(ILogger logger, string message, Exception? exception);

    [LoggerMessage(EventId = 2002, Level = LogLevel.Debug, Message = "{Message}")]
    public static partial void Debug(ILogger logger, string message, Exception? exception);

    [LoggerMessage(EventId = 2003, Level = LogLevel.Information, Message = "{Message}")]
    public static partial void Information(ILogger logger, string message, Exception? exception);

    [LoggerMessage(EventId = 2004, Level = LogLevel.Warning, Message = "{Message}")]
    public static partial void Warning(ILogger logger, string message, Exception? exception);

    [LoggerMessage(EventId = 2005, Level = LogLevel.Error, Message = "{Message}")]
    public static partial void Error(ILogger logger, string message, Exception? exception);
}

using Microsoft.Extensions.Logging;
using Scheduler.Application.Observability;
using Scheduler.Contracts.Execution;

namespace Scheduler.Infrastructure.Observability;

/// <summary>
/// Creates per-execution loggers and progress reporters. Each logger writes to the
/// host log (with an execution scope) and to the per-execution log store, so the
/// output is both structured in the host stream and durable per execution.
/// </summary>
public sealed class ExecutionLoggerFactory : IExecutionLoggerFactory
{
    private readonly IExecutionLogStore _store;
    private readonly ILoggerFactory _loggerFactory;
    private readonly TimeProvider _timeProvider;

    public ExecutionLoggerFactory(
        IExecutionLogStore store,
        ILoggerFactory loggerFactory,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(loggerFactory);
        ArgumentNullException.ThrowIfNull(timeProvider);

        _store = store;
        _loggerFactory = loggerFactory;
        _timeProvider = timeProvider;
    }

    public IJobExecutionLogger CreateLogger(ExecutionIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        return new ExecutionLogger(_store, _loggerFactory.CreateLogger("Scheduler.Execution"), _timeProvider, identity);
    }

    public IJobProgressReporter CreateProgressReporter(ExecutionIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        return new ExecutionProgressReporter(_store, _timeProvider, identity);
    }

    private static void Write(ILogger logger, JobLogLevel level, string message, Exception? exception)
    {
        switch (level)
        {
            case JobLogLevel.Trace:
                ObservabilityLog.Trace(logger, message, exception);
                break;
            case JobLogLevel.Debug:
                ObservabilityLog.Debug(logger, message, exception);
                break;
            case JobLogLevel.Information:
                ObservabilityLog.Information(logger, message, exception);
                break;
            case JobLogLevel.Warning:
                ObservabilityLog.Warning(logger, message, exception);
                break;
            default:
                ObservabilityLog.Error(logger, message, exception);
                break;
        }
    }

    private sealed class ExecutionLogger : IJobExecutionLogger
    {
        private readonly IExecutionLogStore _store;
        private readonly ILogger _logger;
        private readonly TimeProvider _timeProvider;
        private readonly ExecutionIdentity _identity;

        public ExecutionLogger(
            IExecutionLogStore store,
            ILogger logger,
            TimeProvider timeProvider,
            ExecutionIdentity identity)
        {
            _store = store;
            _logger = logger;
            _timeProvider = timeProvider;
            _identity = identity;
        }

        public void Log(JobLogLevel level, string message, Exception? exception = null)
        {
            using IDisposable? scope = _logger.BeginScope(new Dictionary<string, object>
            {
                ["ExecutionId"] = _identity.ExecutionId,
                ["CorrelationId"] = _identity.CorrelationId,
                ["JobId"] = _identity.JobId,
                ["PluginId"] = _identity.PluginId,
                ["PluginVersion"] = _identity.PluginVersion.ToString(),
            });

            Write(_logger, level, message, exception);
            _store.Append(
                _identity.ExecutionId,
                new ExecutionLogEntry(_timeProvider.GetUtcNow(), level.ToString(), message, exception?.Message));
        }
    }

    private sealed class ExecutionProgressReporter : IJobProgressReporter
    {
        private readonly IExecutionLogStore _store;
        private readonly TimeProvider _timeProvider;
        private readonly ExecutionIdentity _identity;

        public ExecutionProgressReporter(
            IExecutionLogStore store,
            TimeProvider timeProvider,
            ExecutionIdentity identity)
        {
            _store = store;
            _timeProvider = timeProvider;
            _identity = identity;
        }

        public void Report(int percent, string? stage = null)
        {
            string message = stage is null ? $"progress {percent}%" : $"progress {percent}% ({stage})";
            _store.Append(
                _identity.ExecutionId,
                new ExecutionLogEntry(_timeProvider.GetUtcNow(), JobLogLevel.Information.ToString(), message, null));
        }
    }
}

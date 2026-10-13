using System.Collections.Generic;
using System.Globalization;
using System.IO.Abstractions;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace Scheduler.Infrastructure.Observability;

/// <summary>
/// A dependency-free rolling file logger: newline-delimited JSON under
/// <c>{LogsRoot}/host-{yyyy-MM-dd}.log</c>, one file per UTC day. It is registered
/// alongside the JSON console sink; both carry the active log scopes so
/// <c>ExecutionId</c>/<c>CorrelationId</c> are visible in the file too.
/// </summary>
public sealed class SimpleFileLoggerProvider : ILoggerProvider
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly IFileSystem _fileSystem;
    private readonly string _logsRoot;
    private readonly LoggerExternalScopeProvider _scopes = new();
    private readonly object _lock = new();
    private DateOnly _currentDay;
    private StreamWriter? _writer;

    public SimpleFileLoggerProvider(string logsRoot, IFileSystem fileSystem)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(logsRoot);
        ArgumentNullException.ThrowIfNull(fileSystem);

        _logsRoot = logsRoot;
        _fileSystem = fileSystem;
    }

    public ILogger CreateLogger(string categoryName) => new FileLogger(this, categoryName, _scopes);

    public void Dispose()
    {
        lock (_lock)
        {
            _writer?.Dispose();
            _writer = null;
        }
    }

    private void Write(string line)
    {
        lock (_lock)
        {
            DateOnly today = DateOnly.FromDateTime(DateTime.UtcNow);
            if (_writer is null || today != _currentDay)
            {
                Roll(today);
            }

            _writer!.WriteLine(line);
        }
    }

    private void Roll(DateOnly day)
    {
        _writer?.Dispose();
        _fileSystem.Directory.CreateDirectory(_logsRoot);
        string path = _fileSystem.Path.Combine(
            _logsRoot,
            $"host-{day.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)}.log");
        _writer = new StreamWriter(_fileSystem.File.Open(path, FileMode.Append, FileAccess.Write, FileShare.Read))
        {
            AutoFlush = true,
        };
        _currentDay = day;
    }

    private sealed class FileLogger : ILogger
    {
        private readonly SimpleFileLoggerProvider _provider;
        private readonly string _category;
        private readonly IExternalScopeProvider _scopes;

        public FileLogger(SimpleFileLoggerProvider provider, string category, IExternalScopeProvider scopes)
        {
            _provider = provider;
            _category = category;
            _scopes = scopes;
        }

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => _scopes.Push(state);

        public bool IsEnabled(LogLevel logLevel) => logLevel != LogLevel.None;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel))
            {
                return;
            }

            Dictionary<string, object?> scopes = [];
            _scopes.ForEachScope(
                (scope, values) =>
                {
                    if (scope is IEnumerable<KeyValuePair<string, object?>> pairs)
                    {
                        foreach (KeyValuePair<string, object?> pair in pairs)
                        {
                            values[pair.Key] = pair.Value;
                        }
                    }
                },
                scopes);

            FileLogRecord record = new(
                DateTimeOffset.UtcNow,
                logLevel.ToString(),
                _category,
                eventId.Id,
                formatter(state, exception),
                exception?.ToString(),
                scopes.Count == 0 ? null : scopes);

            _provider.Write(JsonSerializer.Serialize(record, JsonOptions));
        }
    }

    private sealed record FileLogRecord(
        DateTimeOffset Timestamp,
        string Level,
        string Category,
        int EventId,
        string Message,
        string? Exception,
        IReadOnlyDictionary<string, object?>? Scopes);
}

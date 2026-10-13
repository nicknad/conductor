using System.Globalization;
using System.IO.Abstractions;
using System.Text;
using System.Text.Json;
using Scheduler.Application.Observability;
using Scheduler.Infrastructure.Packaging;

namespace Scheduler.Infrastructure.Observability;

/// <summary>
/// File-backed per-execution log store: one newline-delimited JSON file per
/// execution at <c>{LogsRoot}/{executionId}.log</c>. Chosen over a database table
/// because logs are large and append-heavy and are read one execution at a time,
/// never in aggregate. Writes are serialized; reads stream the file back.
/// </summary>
public sealed class FileExecutionLogStore : IExecutionLogStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly IFileSystem _fileSystem;
    private readonly string _logsRoot;
    private readonly object _writeLock = new();

    public FileExecutionLogStore(PackagingOptions options, IFileSystem fileSystem)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(fileSystem);

        _fileSystem = fileSystem;
        _logsRoot = PackagingPaths.Resolve(options.LogsRoot ?? "logs", options.BaseDirectory, fileSystem);
    }

    public void Append(Guid executionId, ExecutionLogEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);

        string line = JsonSerializer.Serialize(
            new LogLine(entry.Timestamp, entry.Level, entry.Message, entry.Exception),
            JsonOptions) + Environment.NewLine;

        lock (_writeLock)
        {
            _fileSystem.Directory.CreateDirectory(_logsRoot);
            _fileSystem.File.AppendAllText(PathFor(executionId), line, Encoding.UTF8);
        }
    }

    public async Task<IReadOnlyList<ExecutionLogEntry>> ReadAsync(
        Guid executionId,
        CancellationToken cancellationToken = default)
    {
        string path = PathFor(executionId);
        if (!_fileSystem.File.Exists(path))
        {
            return [];
        }

        string[] lines = await _fileSystem.File.ReadAllLinesAsync(path, cancellationToken);
        List<ExecutionLogEntry> entries = [];
        foreach (string line in lines)
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            LogLine? parsed = JsonSerializer.Deserialize<LogLine>(line, JsonOptions);
            if (parsed is not null)
            {
                entries.Add(new ExecutionLogEntry(parsed.Timestamp, parsed.Level, parsed.Message, parsed.Exception));
            }
        }

        return entries;
    }

    public Task TrimAsync(int retained, CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(retained);
        cancellationToken.ThrowIfCancellationRequested();

        if (!_fileSystem.Directory.Exists(_logsRoot))
        {
            return Task.CompletedTask;
        }

        string[] expired = _fileSystem.Directory.GetFiles(_logsRoot, "*.log")
            .Where(IsExecutionLog)
            .OrderByDescending(_fileSystem.File.GetLastWriteTimeUtc)
            .Skip(retained)
            .ToArray();

        foreach (string file in expired)
        {
            try
            {
                _fileSystem.File.Delete(file);
            }
            catch (IOException)
            {
                // A log being written right now is skipped and re-trimmed next startup.
            }
            catch (UnauthorizedAccessException)
            {
            }
        }

        return Task.CompletedTask;
    }

    private bool IsExecutionLog(string path) =>
        Guid.TryParseExact(_fileSystem.Path.GetFileNameWithoutExtension(path), "N", out _);

    private string PathFor(Guid executionId) =>
        _fileSystem.Path.Combine(_logsRoot, executionId.ToString("N", CultureInfo.InvariantCulture) + ".log");

    private sealed record LogLine(DateTimeOffset Timestamp, string Level, string Message, string? Exception);
}

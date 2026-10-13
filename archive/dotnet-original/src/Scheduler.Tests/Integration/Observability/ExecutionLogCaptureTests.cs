using System.IO.Abstractions;
using Microsoft.Extensions.Logging.Abstractions;
using Scheduler.Application.Observability;
using Scheduler.Contracts.Execution;
using Scheduler.Infrastructure.Observability;
using Scheduler.Infrastructure.Packaging;

namespace Scheduler.Tests.Integration.Observability;

public sealed class ExecutionLogCaptureTests : IDisposable
{
    private readonly string _directory;
    private readonly FileSystem _fileSystem = new();
    private readonly FileExecutionLogStore _store;

    public ExecutionLogCaptureTests()
    {
        _directory = Path.Combine(Path.GetTempPath(), "jobscheduler-logs", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_directory);
        PackagingOptions options = new()
        {
            ArtifactsRoot = Path.Combine(_directory, "artifacts"),
            StagingRoot = Path.Combine(_directory, "staging"),
            PublicKeyPath = "key.pem",
            LogsRoot = "logs",
            BaseDirectory = _directory,
        };
        _store = new FileExecutionLogStore(options, _fileSystem);
    }

    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task AppendAndReadRoundTrip()
    {
        Guid executionId = Guid.NewGuid();
        _store.Append(executionId, new ExecutionLogEntry(DateTimeOffset.UnixEpoch, "Information", "hello", null));
        _store.Append(executionId, new ExecutionLogEntry(DateTimeOffset.UnixEpoch.AddSeconds(1), "Error", "boom", "boom"));

        IReadOnlyList<ExecutionLogEntry> entries = await _store.ReadAsync(executionId, CancellationToken);

        Assert.Equal(2, entries.Count);
        Assert.Equal("hello", entries[0].Message);
        Assert.Equal("boom", entries[1].Exception);
    }

    [Fact]
    public async Task ReadingAnUnknownExecutionReturnsEmpty()
    {
        Assert.Empty(await _store.ReadAsync(Guid.NewGuid(), CancellationToken));
    }

    [Fact]
    public async Task TrimKeepsTheMostRecentLogs()
    {
        Guid oldest = Guid.NewGuid();
        Guid middle = Guid.NewGuid();
        Guid newest = Guid.NewGuid();
        _store.Append(oldest, new ExecutionLogEntry(DateTimeOffset.UnixEpoch, "Information", "a", null));
        _store.Append(middle, new ExecutionLogEntry(DateTimeOffset.UnixEpoch, "Information", "b", null));
        _store.Append(newest, new ExecutionLogEntry(DateTimeOffset.UnixEpoch, "Information", "c", null));

        string logsRoot = _fileSystem.Path.Combine(_directory, "logs");
        _fileSystem.File.SetLastWriteTimeUtc(_fileSystem.Path.Combine(logsRoot, oldest.ToString("N") + ".log"), new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        _fileSystem.File.SetLastWriteTimeUtc(_fileSystem.Path.Combine(logsRoot, middle.ToString("N") + ".log"), new DateTime(2021, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        _fileSystem.File.SetLastWriteTimeUtc(_fileSystem.Path.Combine(logsRoot, newest.ToString("N") + ".log"), new DateTime(2022, 1, 1, 0, 0, 0, DateTimeKind.Utc));

        await _store.TrimAsync(retained: 2, CancellationToken);

        Assert.Empty(await _store.ReadAsync(oldest, CancellationToken));
        Assert.Single(await _store.ReadAsync(middle, CancellationToken));
        Assert.Single(await _store.ReadAsync(newest, CancellationToken));
    }

    [Fact]
    public async Task LoggerFactoryCapturesPluginLogsPerExecution()
    {
        ExecutionLoggerFactory factory = new(_store, NullLoggerFactory.Instance, TimeProvider.System);
        ExecutionIdentity identity = new(Guid.NewGuid(), "corr-1", "job-1", "plugin-1", new Version(1, 0, 0));

        IJobExecutionLogger logger = factory.CreateLogger(identity);
        logger.Log(JobLogLevel.Warning, "something happened");

        IReadOnlyList<ExecutionLogEntry> entries = await _store.ReadAsync(identity.ExecutionId, CancellationToken);
        ExecutionLogEntry entry = Assert.Single(entries);
        Assert.Equal("Warning", entry.Level);
        Assert.Equal("something happened", entry.Message);
    }

    [Fact]
    public async Task ProgressReporterIsCaptured()
    {
        ExecutionLoggerFactory factory = new(_store, NullLoggerFactory.Instance, TimeProvider.System);
        ExecutionIdentity identity = new(Guid.NewGuid(), "corr-2", "job-1", "plugin-1", new Version(1, 0, 0));

        factory.CreateProgressReporter(identity).Report(50, "halfway");

        IReadOnlyList<ExecutionLogEntry> entries = await _store.ReadAsync(identity.ExecutionId, CancellationToken);
        ExecutionLogEntry entry = Assert.Single(entries);
        Assert.Contains("50%", entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TrimWithNoExcessKeepsAllLogs()
    {
        Guid executionId = Guid.NewGuid();
        _store.Append(executionId, new ExecutionLogEntry(DateTimeOffset.UnixEpoch, "Information", "a", null));

        await _store.TrimAsync(retained: 5, CancellationToken);

        Assert.Single(await _store.ReadAsync(executionId, CancellationToken));
    }

    [Fact]
    public async Task TrimIgnoresNonExecutionFiles()
    {
        string logsRoot = _fileSystem.Path.Combine(_directory, "logs");
        _fileSystem.Directory.CreateDirectory(logsRoot);
        string hostLog = _fileSystem.Path.Combine(logsRoot, "host-2026-01-01.log");
        _fileSystem.File.WriteAllText(hostLog, "host log line");

        await _store.TrimAsync(retained: 1, CancellationToken);

        Assert.True(_fileSystem.File.Exists(hostLog));
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (DirectoryNotFoundException)
        {
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}

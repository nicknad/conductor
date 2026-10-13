using Scheduler.Contracts.Execution;

namespace Scheduler.Runtime.Worker.Ipc;

/// <summary>Versioned message contract for the local IPC channel between host and worker.</summary>
public sealed record WorkerProtocol
{
    public const int Version = 1;
}

public sealed record WorkerExecuteRequest(
    int ProtocolVersion,
    Guid ExecutionId,
    string JobId,
    string PluginId,
    string PluginVersion,
    int ConfigurationRevision,
    DateTimeOffset Deadline,
    IReadOnlyDictionary<string, string?> Parameters,
    IReadOnlyCollection<string> SecretReferences);

public sealed record WorkerExecuteResponse(
    Guid ExecutionId,
    JobOutcome Outcome,
    string? Summary,
    IReadOnlyDictionary<string, string?> Data);

public sealed record WorkerCancelRequest(Guid ExecutionId);

public sealed record WorkerProgressEvent(
    Guid ExecutionId,
    int Percent,
    string? Stage);

public sealed record WorkerLogEvent(
    Guid ExecutionId,
    JobLogLevel Level,
    string Message);

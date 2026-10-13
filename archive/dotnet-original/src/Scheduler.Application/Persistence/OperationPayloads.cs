namespace Scheduler.Application.Persistence;

/// <summary>
/// Payload of an <see cref="OperationKind.Install" /> operation: carries enough
/// state to resume promotion or discard staging after a crash.
/// </summary>
public sealed record InstallOperationPayload(string? StagingRoot, string? PluginId, string? Version)
{
    public const int CurrentVersion = 1;

    public int PayloadVersion { get; init; } = CurrentVersion;

    public string? Error { get; init; }
}

/// <summary>
/// Payload of a lifecycle operation (activate / deactivate / rollback / remove).
/// The reconciler reads it to decide whether an interrupted operation completed
/// or must be rolled back.
/// </summary>
public sealed record LifecycleOperationPayload(string PluginId, string? Version)
{
    public const int CurrentVersion = 1;

    public int PayloadVersion { get; init; } = CurrentVersion;

    public string? Error { get; init; }

    public string? UncleanUnload { get; init; }
}

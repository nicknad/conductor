namespace Scheduler.Application.Persistence;

/// <summary>
/// The atomically published desired active version for a plugin. There is at
/// most one activation row per plugin, which makes "active" unambiguous.
/// </summary>
public sealed record PluginActivationRecord
{
    public required string PluginId { get; init; }

    public required Version Version { get; init; }

    public required DateTimeOffset ActivatedAt { get; init; }

    public required string ActivatedBy { get; init; }
}

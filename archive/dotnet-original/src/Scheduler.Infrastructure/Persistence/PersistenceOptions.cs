namespace Scheduler.Infrastructure.Persistence;

/// <summary>
/// Explicit, configuration-driven persistence locations. Relative paths resolve
/// against <see cref="BaseDirectory" /> (the host content root), never the
/// process working directory.
/// </summary>
public sealed class PersistenceOptions
{
    public required string DatabasePath { get; init; }

    public string? BaseDirectory { get; init; }
}

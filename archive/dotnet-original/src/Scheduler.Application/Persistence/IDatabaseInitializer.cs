namespace Scheduler.Application.Persistence;

/// <summary>
/// Applies the registry schema at startup. Migrations are forward-only,
/// versioned, and idempotent: re-running only applies pending versions.
/// </summary>
public interface IDatabaseInitializer
{
    Task InitializeAsync(CancellationToken cancellationToken = default);

    /// <summary>Returns the highest applied schema version, or zero when uninitialized.</summary>
    Task<int> GetSchemaVersionAsync(CancellationToken cancellationToken = default);
}

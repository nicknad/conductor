namespace Scheduler.Infrastructure.Persistence;

/// <summary>
/// One forward-only, ordered schema migration. <see cref="Sql" /> may contain
/// multiple statements; applied migrations are recorded via SQLite's
/// <c>user_version</c> and never re-applied.
/// </summary>
public sealed record Migration(int Version, string Name, string Sql);

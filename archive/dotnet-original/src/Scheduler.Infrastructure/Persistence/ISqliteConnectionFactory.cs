using Microsoft.Data.Sqlite;

namespace Scheduler.Infrastructure.Persistence;

/// <summary>
/// Opens ready-to-use SQLite connections with the platform's required pragmas
/// (WAL journaling, foreign keys, and a bounded busy timeout).
/// </summary>
public interface ISqliteConnectionFactory
{
    Task<SqliteConnection> OpenConnectionAsync(CancellationToken cancellationToken = default);
}

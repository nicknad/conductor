using System.Data.Common;
using System.Globalization;
using Quartz.Impl.AdoJobStore.Common;

namespace Scheduler.Infrastructure.Scheduling;

/// <summary>
/// Applies the same connection pragmas as the registry's
/// <c>SqliteConnectionFactory</c> — WAL, foreign keys, and a bounded busy timeout
/// — to every connection Quartz opens, so the scheduler store shares the
/// database's concurrency behavior.
/// </summary>
public sealed class PragmaApplyingDbProvider : DbProvider
{
    private readonly int _busyTimeoutMilliseconds;

    public PragmaApplyingDbProvider(string providerName, string connectionString, int busyTimeoutMilliseconds)
        : base(providerName, connectionString)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(busyTimeoutMilliseconds);
        _busyTimeoutMilliseconds = busyTimeoutMilliseconds;
    }

    public override DbConnection CreateConnection()
    {
        DbConnection connection = base.CreateConnection();
        try
        {
            connection.Open();
            using DbCommand command = connection.CreateCommand();
            command.CommandText =
                "PRAGMA journal_mode=WAL;" +
                "PRAGMA foreign_keys=ON;" +
                "PRAGMA busy_timeout=" +
                _busyTimeoutMilliseconds.ToString(CultureInfo.InvariantCulture) +
                ";";
            command.ExecuteNonQuery();
            return connection;
        }
        catch
        {
            connection.Dispose();
            throw;
        }
    }
}

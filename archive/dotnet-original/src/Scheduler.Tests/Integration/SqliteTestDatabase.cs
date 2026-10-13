using System.IO.Abstractions;
using Microsoft.Data.Sqlite;
using Scheduler.Infrastructure.Persistence;

namespace Scheduler.Tests.Integration;

/// <summary>
/// A throwaway SQLite registry under a per-test temp directory. The directory
/// and pooled connections are released on dispose.
/// </summary>
internal sealed class SqliteTestDatabase : IDisposable
{
    private readonly string _directory;

    public SqliteTestDatabase()
    {
        _directory = Path.Combine(Path.GetTempPath(), "jobscheduler-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_directory);

        Options = new PersistenceOptions
        {
            DatabasePath = Path.Combine(_directory, "registry.db"),
        };
        ConnectionFactory = new SqliteConnectionFactory(Options, new FileSystem());
        Initializer = new SqliteDatabaseInitializer(ConnectionFactory, SchemaMigrations.All);
        UnitOfWorkFactory = new SqliteRegistryUnitOfWorkFactory(ConnectionFactory);
    }

    public PersistenceOptions Options { get; }

    public SqliteConnectionFactory ConnectionFactory { get; }

    public SqliteDatabaseInitializer Initializer { get; }

    public SqliteRegistryUnitOfWorkFactory UnitOfWorkFactory { get; }

    public Task InitializeAsync(CancellationToken cancellationToken = default) =>
        Initializer.InitializeAsync(cancellationToken);

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();

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

using System.Globalization;
using System.IO.Abstractions;
using Microsoft.Data.Sqlite;

namespace Scheduler.Infrastructure.Persistence;

/// <summary>
/// Creates SQLite connections against an explicit database path. The target
/// directory is created on construction; WAL mode, foreign keys, and a busy
/// timeout are applied to every connection. File-system access is injected so
/// directory-provisioning failures are testable.
/// </summary>
public sealed class SqliteConnectionFactory : ISqliteConnectionFactory
{
    private const int DefaultBusyTimeoutMilliseconds = 5000;

    private readonly string _connectionString;
    private readonly int _busyTimeoutMilliseconds;

    public SqliteConnectionFactory(PersistenceOptions options, IFileSystem fileSystem)
        : this(options, fileSystem, DefaultBusyTimeoutMilliseconds)
    {
    }

    public SqliteConnectionFactory(PersistenceOptions options, IFileSystem fileSystem, int busyTimeoutMilliseconds)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(fileSystem);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(busyTimeoutMilliseconds);

        string databasePath = ResolveDatabasePath(options, fileSystem);
        EnsureDirectory(fileSystem, databasePath);

        DatabasePath = databasePath;
        _connectionString = new SqliteConnectionStringBuilder { DataSource = databasePath }.ToString();
        _busyTimeoutMilliseconds = busyTimeoutMilliseconds;
    }

    /// <summary>The absolute database path, resolved from the configured root.</summary>
    public string DatabasePath { get; }

    public async Task<SqliteConnection> OpenConnectionAsync(CancellationToken cancellationToken = default)
    {
        SqliteConnection connection = new(_connectionString);
        try
        {
            await connection.OpenAsync(cancellationToken);
            await ApplyPragmasAsync(connection, cancellationToken);
            return connection;
        }
        catch
        {
            await connection.DisposeAsync();
            throw;
        }
    }

    private async Task ApplyPragmasAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        await using (SqliteCommand journalMode = connection.CreateCommand())
        {
            journalMode.CommandText = "PRAGMA journal_mode = WAL;";
            await journalMode.ExecuteScalarAsync(cancellationToken);
        }

        await using (SqliteCommand foreignKeys = connection.CreateCommand())
        {
            foreignKeys.CommandText = "PRAGMA foreign_keys = ON;";
            await foreignKeys.ExecuteNonQueryAsync(cancellationToken);
        }

        await using (SqliteCommand busyTimeout = connection.CreateCommand())
        {
            busyTimeout.CommandText =
                "PRAGMA busy_timeout = " +
                _busyTimeoutMilliseconds.ToString(CultureInfo.InvariantCulture) +
                ";";
            await busyTimeout.ExecuteNonQueryAsync(cancellationToken);
        }
    }

    private static string ResolveDatabasePath(PersistenceOptions options, IFileSystem fileSystem)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(options.DatabasePath);

        if (fileSystem.Path.IsPathRooted(options.DatabasePath))
        {
            return options.DatabasePath;
        }

        if (string.IsNullOrEmpty(options.BaseDirectory))
        {
            throw new InvalidOperationException(
                "DatabasePath must be rooted when no BaseDirectory is configured.");
        }

        return fileSystem.Path.GetFullPath(fileSystem.Path.Combine(options.BaseDirectory, options.DatabasePath));
    }

    private static void EnsureDirectory(IFileSystem fileSystem, string databasePath)
    {
        string? directory = fileSystem.Path.GetDirectoryName(fileSystem.Path.GetFullPath(databasePath));
        if (!string.IsNullOrEmpty(directory))
        {
            fileSystem.Directory.CreateDirectory(directory);
        }
    }
}

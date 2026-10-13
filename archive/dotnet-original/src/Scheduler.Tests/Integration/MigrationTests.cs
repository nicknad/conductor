using System.Globalization;
using System.IO.Abstractions;
using Microsoft.Data.Sqlite;
using Scheduler.Application.Persistence;
using Scheduler.Infrastructure.Persistence;

namespace Scheduler.Tests.Integration;

public sealed class MigrationTests
{
    private static readonly string[] ExpectedTables =
    [
        "plugin_versions",
        "plugin_activation",
        "jobs",
        "executions",
        "audit_log",
        "operations",
    ];

    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task InitializationCreatesRegistrySchema()
    {
        using SqliteTestDatabase database = new();

        await database.InitializeAsync(CancellationToken);

        await using SqliteConnection connection = await database.ConnectionFactory.OpenConnectionAsync(CancellationToken);
        Assert.Equal(SchemaMigrations.LatestVersion, await ReadIntAsync(connection, "PRAGMA user_version;"));

        foreach (string table in ExpectedTables)
        {
            Assert.True(await TableExistsAsync(connection, table), $"Expected table '{table}' to exist.");
        }
    }

    [Fact]
    public async Task ReinitializationIsIdempotentAndPreservesData()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);

        await using (IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken))
        {
            await unitOfWork.Audit.WriteAsync(
                new AuditEntry
                {
                    Timestamp = DateTimeOffset.UnixEpoch,
                    Actor = "tester",
                    Action = "seed",
                    Target = "registry",
                },
                CancellationToken);
            await unitOfWork.CommitAsync(CancellationToken);
        }

        await database.InitializeAsync(CancellationToken);

        Assert.Equal(SchemaMigrations.LatestVersion, await database.Initializer.GetSchemaVersionAsync(CancellationToken));

        await using IRegistryUnitOfWork read = await database.UnitOfWorkFactory.BeginAsync(CancellationToken);
        IReadOnlyList<AuditEntry> entries = await read.Audit.ListAsync(cancellationToken: CancellationToken);
        Assert.Single(entries);
        Assert.Equal("seed", entries[0].Action);
    }

    [Fact]
    public async Task UninitializedDatabaseReportsVersionZero()
    {
        using SqliteTestDatabase database = new();

        Assert.Equal(0, await database.Initializer.GetSchemaVersionAsync(CancellationToken));
    }

    [Fact]
    public async Task ConnectionsUseWriteAheadLogging()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);

        await using SqliteConnection connection = await database.ConnectionFactory.OpenConnectionAsync(CancellationToken);

        Assert.Equal("wal", await ReadStringAsync(connection, "PRAGMA journal_mode;"));
    }

    [Fact]
    public async Task OpenedConnectionsEnforceForeignKeys()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);

        await using SqliteConnection connection = await database.ConnectionFactory.OpenConnectionAsync(CancellationToken);
        await ExecuteAsync(
            connection,
            "CREATE TABLE parent (id INTEGER PRIMARY KEY); " +
            "CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id));");
        await ExecuteAsync(connection, "INSERT INTO parent (id) VALUES (1);");
        await ExecuteAsync(connection, "INSERT INTO child (id, parent_id) VALUES (1, 1);");

        await Assert.ThrowsAsync<SqliteException>(
            () => ExecuteAsync(connection, "INSERT INTO child (id, parent_id) VALUES (2, 99);"));
    }

    [Fact]
    public async Task OpenedConnectionsApplyConfiguredBusyTimeout()
    {
        using SqliteTestDatabase database = new();
        SqliteConnectionFactory factory = new(database.Options, new FileSystem(), busyTimeoutMilliseconds: 1234);

        await using SqliteConnection connection = await factory.OpenConnectionAsync(CancellationToken);

        Assert.Equal(1234, await ReadIntAsync(connection, "PRAGMA busy_timeout;"));
    }

    [Fact]
    public async Task AppliesPendingMigrationsInOrder()
    {
        using SqliteTestDatabase database = new();
        SqliteDatabaseInitializer initializer = new(
            database.ConnectionFactory,
            [
                new Migration(1, "one", "CREATE TABLE first (id INTEGER PRIMARY KEY);"),
                new Migration(2, "two", "CREATE TABLE second (id INTEGER PRIMARY KEY);"),
                new Migration(3, "three", "CREATE TABLE third (id INTEGER PRIMARY KEY);"),
            ]);

        await initializer.InitializeAsync(CancellationToken);

        await using SqliteConnection connection = await database.ConnectionFactory.OpenConnectionAsync(CancellationToken);
        Assert.Equal(3, await ReadIntAsync(connection, "PRAGMA user_version;"));
        Assert.True(await TableExistsAsync(connection, "first"));
        Assert.True(await TableExistsAsync(connection, "second"));
        Assert.True(await TableExistsAsync(connection, "third"));
    }

    [Fact]
    public async Task FailedMigrationIsRolledBackAndDoesNotAdvanceVersion()
    {
        using SqliteTestDatabase database = new();
        SqliteDatabaseInitializer initializer = new(
            database.ConnectionFactory,
            [
                new Migration(1, "one", "CREATE TABLE first (id INTEGER PRIMARY KEY);"),
                new Migration(2, "two", "CREATE TABLE second (id INTEGER PRIMARY KEY); THIS IS NOT SQL;"),
            ]);

        await Assert.ThrowsAsync<SqliteException>(() => initializer.InitializeAsync(CancellationToken));

        await using SqliteConnection connection = await database.ConnectionFactory.OpenConnectionAsync(CancellationToken);
        Assert.Equal(1, await ReadIntAsync(connection, "PRAGMA user_version;"));
        Assert.True(await TableExistsAsync(connection, "first"));
        Assert.False(await TableExistsAsync(connection, "second"));
    }

    [Fact]
    public async Task AlreadyAppliedMigrationsAreNotReapplied()
    {
        using SqliteTestDatabase database = new();
        SqliteDatabaseInitializer firstRun = new(
            database.ConnectionFactory,
            [
                new Migration(1, "one", "CREATE TABLE first (id INTEGER PRIMARY KEY);"),
                new Migration(2, "two", "CREATE TABLE second (id INTEGER PRIMARY KEY);"),
            ]);
        await firstRun.InitializeAsync(CancellationToken);

        await using (SqliteConnection connection = await database.ConnectionFactory.OpenConnectionAsync(CancellationToken))
        {
            await ExecuteAsync(connection, "INSERT INTO first (id) VALUES (1);");
        }

        SqliteDatabaseInitializer secondRun = new(
            database.ConnectionFactory,
            [
                new Migration(1, "one", "CREATE TABLE first (id INTEGER PRIMARY KEY);"),
                new Migration(2, "two", "CREATE TABLE second (id INTEGER PRIMARY KEY);"),
                new Migration(3, "three", "CREATE TABLE third (id INTEGER PRIMARY KEY);"),
            ]);
        await secondRun.InitializeAsync(CancellationToken);

        await using SqliteConnection verify = await database.ConnectionFactory.OpenConnectionAsync(CancellationToken);
        Assert.Equal(3, await ReadIntAsync(verify, "PRAGMA user_version;"));
        Assert.Equal(1, await ReadIntAsync(verify, "SELECT COUNT(*) FROM first;"));
        Assert.True(await TableExistsAsync(verify, "third"));
    }

    private static async Task ExecuteAsync(SqliteConnection connection, string sql)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(CancellationToken);
    }

    private static async Task<bool> TableExistsAsync(SqliteConnection connection, string tableName)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = $name;";
        command.Parameters.AddWithValue("$name", tableName);

        object? result = await command.ExecuteScalarAsync(CancellationToken);
        return Convert.ToInt64(result, CultureInfo.InvariantCulture) > 0;
    }

    private static async Task<int> ReadIntAsync(SqliteConnection connection, string sql)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = sql;
        object? result = await command.ExecuteScalarAsync(CancellationToken);
        return Convert.ToInt32(result, CultureInfo.InvariantCulture);
    }

    private static async Task<string?> ReadStringAsync(SqliteConnection connection, string sql)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = sql;
        object? result = await command.ExecuteScalarAsync(CancellationToken);
        return Convert.ToString(result, CultureInfo.InvariantCulture);
    }
}

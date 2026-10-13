using System.Globalization;
using Microsoft.Data.Sqlite;
using Scheduler.Application.Persistence;

namespace Scheduler.Infrastructure.Persistence;

/// <summary>
/// Applies the registry schema forward-only and idempotently. Each pending
/// migration runs in its own transaction and records its version via
/// <c>user_version</c>, so a partially-applied run resumes cleanly.
/// </summary>
public sealed class SqliteDatabaseInitializer : IDatabaseInitializer
{
    private readonly ISqliteConnectionFactory _connectionFactory;
    private readonly IReadOnlyList<Migration> _migrations;

    public SqliteDatabaseInitializer(ISqliteConnectionFactory connectionFactory, IReadOnlyList<Migration> migrations)
    {
        ArgumentNullException.ThrowIfNull(connectionFactory);
        ArgumentNullException.ThrowIfNull(migrations);

        _connectionFactory = connectionFactory;
        _migrations = [.. migrations.OrderBy(migration => migration.Version)];
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await using SqliteConnection connection = await _connectionFactory.OpenConnectionAsync(cancellationToken);

        int currentVersion = await ReadSchemaVersionAsync(connection, cancellationToken);
        foreach (Migration migration in _migrations)
        {
            if (migration.Version <= currentVersion)
            {
                continue;
            }

            await ApplyMigrationAsync(connection, migration, cancellationToken);
            currentVersion = migration.Version;
        }
    }

    public async Task<int> GetSchemaVersionAsync(CancellationToken cancellationToken = default)
    {
        await using SqliteConnection connection = await _connectionFactory.OpenConnectionAsync(cancellationToken);
        return await ReadSchemaVersionAsync(connection, cancellationToken);
    }

    private static async Task ApplyMigrationAsync(
        SqliteConnection connection,
        Migration migration,
        CancellationToken cancellationToken)
    {
        await using SqliteTransaction transaction =
            (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);

        await using (SqliteCommand schema = connection.CreateCommand())
        {
            schema.Transaction = transaction;
            schema.CommandText = migration.Sql;
            await schema.ExecuteNonQueryAsync(cancellationToken);
        }

        await using (SqliteCommand version = connection.CreateCommand())
        {
            version.Transaction = transaction;
            version.CommandText =
                "PRAGMA user_version = " + migration.Version.ToString(CultureInfo.InvariantCulture) + ";";
            await version.ExecuteNonQueryAsync(cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
    }

    private static async Task<int> ReadSchemaVersionAsync(
        SqliteConnection connection,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "PRAGMA user_version;";
        object? result = await command.ExecuteScalarAsync(cancellationToken);
        return Convert.ToInt32(result, CultureInfo.InvariantCulture);
    }
}

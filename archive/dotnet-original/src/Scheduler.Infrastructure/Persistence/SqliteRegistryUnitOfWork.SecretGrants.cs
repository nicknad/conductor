using Microsoft.Data.Sqlite;
using Scheduler.Application.Secrets;

namespace Scheduler.Infrastructure.Persistence;

internal sealed partial class SqliteRegistryUnitOfWork
{
    private const string PluginWideJob = "";

    public async Task GrantAsync(SecretGrant grant, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(grant);

        await using SqliteCommand command = CreateCommand(
            """
            INSERT INTO secret_grants (plugin_id, job_id, secret_reference, granted_by, granted_at)
            VALUES ($pluginId, $jobId, $reference, $grantedBy, $grantedAt)
            ON CONFLICT (plugin_id, job_id, secret_reference)
            DO UPDATE SET granted_by = excluded.granted_by, granted_at = excluded.granted_at;
            """);
        command.Parameters.AddWithValue("$pluginId", grant.PluginId);
        command.Parameters.AddWithValue("$jobId", grant.JobId ?? PluginWideJob);
        command.Parameters.AddWithValue("$reference", grant.SecretReference);
        command.Parameters.AddWithValue("$grantedBy", grant.GrantedBy);
        command.Parameters.AddWithValue("$grantedAt", DbTimestamp.Format(grant.GrantedAt));

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<bool> RevokeAsync(
        string pluginId,
        string? jobId,
        string secretReference,
        CancellationToken cancellationToken = default)
    {
        await using SqliteCommand command = CreateCommand(
            """
            DELETE FROM secret_grants
             WHERE plugin_id = $pluginId AND job_id = $jobId AND secret_reference = $reference;
            """);
        command.Parameters.AddWithValue("$pluginId", pluginId);
        command.Parameters.AddWithValue("$jobId", jobId ?? PluginWideJob);
        command.Parameters.AddWithValue("$reference", secretReference);

        return await command.ExecuteNonQueryAsync(cancellationToken) > 0;
    }

    public async Task<IReadOnlyList<SecretGrant>> ListAsync(
        string pluginId,
        CancellationToken cancellationToken = default)
    {
        await using SqliteCommand command = CreateCommand(
            "SELECT plugin_id, job_id, secret_reference, granted_by, granted_at " +
            "FROM secret_grants WHERE plugin_id = $pluginId ORDER BY secret_reference;");
        command.Parameters.AddWithValue("$pluginId", pluginId);

        return await ReadGrantsAsync(command, cancellationToken);
    }

    private static async Task<IReadOnlyList<SecretGrant>> ReadGrantsAsync(
        SqliteCommand command,
        CancellationToken cancellationToken)
    {
        List<SecretGrant> grants = [];
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            grants.Add(ReadGrant(reader));
        }

        return grants;
    }

    private static SecretGrant ReadGrant(SqliteDataReader reader)
    {
        string jobId = reader.GetString(1);
        return new SecretGrant
        {
            PluginId = reader.GetString(0),
            JobId = jobId.Length == 0 ? null : jobId,
            SecretReference = reader.GetString(2),
            GrantedBy = reader.GetString(3),
            GrantedAt = DbTimestamp.Parse(reader.GetString(4)),
        };
    }
}

using Microsoft.Data.Sqlite;
using Scheduler.Application.Persistence;
using Scheduler.Application.PluginManagement;
using Scheduler.Contracts.Execution;

namespace Scheduler.Infrastructure.Persistence;

internal sealed partial class SqliteRegistryUnitOfWork
{
    private const string PluginVersionColumns =
        "plugin_id, version, contract_version, entry_assembly, entry_type, execution_mode, " +
        "artifact_hash, state, installed_at, validated_at, validation_error, " +
        "manifest_json, staging_path, artifact_path, unclean_unload_reason";

    public async Task<PluginVersionRecord?> GetVersionAsync(
        string pluginId,
        Version version,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pluginId);
        ArgumentNullException.ThrowIfNull(version);

        await using SqliteCommand command = CreateCommand(
            "SELECT " + PluginVersionColumns +
            " FROM plugin_versions WHERE plugin_id = $pluginId AND version = $version;");
        command.Parameters.AddWithValue("$pluginId", pluginId);
        command.Parameters.AddWithValue("$version", version.ToString());

        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadPluginVersion(reader) : null;
    }

    public async Task<IReadOnlyList<PluginVersionRecord>> ListVersionsAsync(
        string pluginId,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pluginId);

        await using SqliteCommand command = CreateCommand(
            "SELECT " + PluginVersionColumns +
            " FROM plugin_versions WHERE plugin_id = $pluginId ORDER BY installed_at;");
        command.Parameters.AddWithValue("$pluginId", pluginId);

        List<PluginVersionRecord> versions = [];
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            versions.Add(ReadPluginVersion(reader));
        }

        return versions;
    }

    public async Task<IReadOnlyList<string>> ListPluginIdsAsync(CancellationToken cancellationToken = default)
    {
        await using SqliteCommand command = CreateCommand(
            "SELECT DISTINCT plugin_id FROM plugin_versions ORDER BY plugin_id;");

        List<string> pluginIds = [];
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            pluginIds.Add(reader.GetString(0));
        }

        return pluginIds;
    }

    public async Task UpsertVersionAsync(
        PluginVersionRecord version,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(version);

        await using SqliteCommand command = CreateCommand(
            """
            INSERT INTO plugin_versions
                (plugin_id, version, contract_version, entry_assembly, entry_type, execution_mode,
                 artifact_hash, state, installed_at, validated_at, validation_error,
                 manifest_json, staging_path, artifact_path)
            VALUES
                ($pluginId, $version, $contractVersion, $entryAssembly, $entryType, $executionMode,
                 $artifactHash, $state, $installedAt, $validatedAt, $validationError,
                 $manifestJson, $stagingPath, $artifactPath)
            ON CONFLICT(plugin_id, version) DO UPDATE SET
                contract_version = excluded.contract_version,
                entry_assembly   = excluded.entry_assembly,
                entry_type       = excluded.entry_type,
                execution_mode   = excluded.execution_mode,
                artifact_hash    = excluded.artifact_hash,
                state            = excluded.state,
                installed_at     = excluded.installed_at,
                validated_at     = excluded.validated_at,
                validation_error = excluded.validation_error,
                manifest_json    = excluded.manifest_json,
                staging_path     = excluded.staging_path,
                artifact_path    = excluded.artifact_path;
            """);
        command.Parameters.AddWithValue("$pluginId", version.PluginId);
        command.Parameters.AddWithValue("$version", version.Version.ToString());
        command.Parameters.AddWithValue("$contractVersion", version.ContractVersion);
        command.Parameters.AddWithValue("$entryAssembly", version.EntryAssembly);
        command.Parameters.AddWithValue("$entryType", version.EntryType);
        command.Parameters.AddWithValue("$executionMode", version.ExecutionMode.ToString());
        command.Parameters.AddWithValue("$artifactHash", version.ArtifactHash);
        command.Parameters.AddWithValue("$state", version.State.ToString());
        command.Parameters.AddWithValue("$installedAt", DbTimestamp.Format(version.InstalledAt));
        command.Parameters.AddWithValue(
            "$validatedAt",
            version.ValidatedAt.HasValue ? DbTimestamp.Format(version.ValidatedAt.Value) : DBNull.Value);
        command.Parameters.AddWithValue("$validationError", version.ValidationError ?? (object)DBNull.Value);
        command.Parameters.AddWithValue("$manifestJson", version.ManifestJson ?? (object)DBNull.Value);
        command.Parameters.AddWithValue("$stagingPath", version.StagingPath ?? (object)DBNull.Value);
        command.Parameters.AddWithValue("$artifactPath", version.ArtifactPath ?? (object)DBNull.Value);

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task SetStagedAsync(
        string pluginId,
        Version version,
        string artifactPath,
        DateTimeOffset validatedAt,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pluginId);
        ArgumentNullException.ThrowIfNull(version);
        ArgumentException.ThrowIfNullOrWhiteSpace(artifactPath);

        await using SqliteCommand command = CreateCommand(
            """
            UPDATE plugin_versions
               SET state        = $stagedState,
                   artifact_path = $artifactPath,
                   staging_path  = NULL,
                   validated_at  = $validatedAt,
                   validation_error = NULL
             WHERE plugin_id = $pluginId AND version = $version;
            """);
        command.Parameters.AddWithValue("$stagedState", PluginLifecycleState.Staged.ToString());
        command.Parameters.AddWithValue("$artifactPath", artifactPath);
        command.Parameters.AddWithValue("$validatedAt", DbTimestamp.Format(validatedAt));
        command.Parameters.AddWithValue("$pluginId", pluginId);
        command.Parameters.AddWithValue("$version", version.ToString());

        int affected = await command.ExecuteNonQueryAsync(cancellationToken);
        if (affected == 0)
        {
            throw new KeyNotFoundException(
                $"Plugin version '{pluginId}' '{version}' was not found.");
        }
    }

    public async Task SetVersionStateAsync(
        string pluginId,
        Version version,
        PluginLifecycleState state,
        string? validationError = null,
        DateTimeOffset? validatedAt = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pluginId);
        ArgumentNullException.ThrowIfNull(version);

        await using SqliteCommand command = CreateCommand(
            """
            UPDATE plugin_versions
               SET state = $state,
                   validation_error = $validationError,
                   validated_at = COALESCE($validatedAt, validated_at)
             WHERE plugin_id = $pluginId AND version = $version;
            """);
        command.Parameters.AddWithValue("$state", state.ToString());
        command.Parameters.AddWithValue("$validationError", validationError ?? (object)DBNull.Value);
        command.Parameters.AddWithValue(
            "$validatedAt",
            validatedAt.HasValue ? DbTimestamp.Format(validatedAt.Value) : DBNull.Value);
        command.Parameters.AddWithValue("$pluginId", pluginId);
        command.Parameters.AddWithValue("$version", version.ToString());

        int affected = await command.ExecuteNonQueryAsync(cancellationToken);
        if (affected == 0)
        {
            throw new KeyNotFoundException(
                $"Plugin version '{pluginId}' '{version}' was not found.");
        }
    }

    public async Task<PluginActivationRecord?> GetActivationAsync(
        string pluginId,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pluginId);

        await using SqliteCommand command = CreateCommand(
            "SELECT plugin_id, version, activated_at, activated_by FROM plugin_activation WHERE plugin_id = $pluginId;");
        command.Parameters.AddWithValue("$pluginId", pluginId);

        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken)
            ? new PluginActivationRecord
            {
                PluginId = reader.GetString(0),
                Version = Version.Parse(reader.GetString(1)),
                ActivatedAt = DbTimestamp.Parse(reader.GetString(2)),
                ActivatedBy = reader.GetString(3),
            }
            : null;
    }

    public async Task SetActivationAsync(
        PluginActivationRecord activation,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(activation);

        await using SqliteCommand command = CreateCommand(
            """
            INSERT INTO plugin_activation (plugin_id, version, activated_at, activated_by)
            VALUES ($pluginId, $version, $activatedAt, $activatedBy)
            ON CONFLICT(plugin_id) DO UPDATE SET
                version      = excluded.version,
                activated_at = excluded.activated_at,
                activated_by = excluded.activated_by;
            """);
        command.Parameters.AddWithValue("$pluginId", activation.PluginId);
        command.Parameters.AddWithValue("$version", activation.Version.ToString());
        command.Parameters.AddWithValue("$activatedAt", DbTimestamp.Format(activation.ActivatedAt));
        command.Parameters.AddWithValue("$activatedBy", activation.ActivatedBy);

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task ClearActivationAsync(string pluginId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pluginId);

        await using SqliteCommand command = CreateCommand(
            "DELETE FROM plugin_activation WHERE plugin_id = $pluginId;");
        command.Parameters.AddWithValue("$pluginId", pluginId);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task SetUncleanUnloadAsync(
        string pluginId,
        Version version,
        string reason,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pluginId);
        ArgumentNullException.ThrowIfNull(version);
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);

        await using SqliteCommand command = CreateCommand(
            """
            UPDATE plugin_versions
               SET unclean_unload_reason = $reason
             WHERE plugin_id = $pluginId AND version = $version;
            """);
        command.Parameters.AddWithValue("$reason", reason);
        command.Parameters.AddWithValue("$pluginId", pluginId);
        command.Parameters.AddWithValue("$version", version.ToString());

        int affected = await command.ExecuteNonQueryAsync(cancellationToken);
        if (affected == 0)
        {
            throw new KeyNotFoundException(
                $"Plugin version '{pluginId}' '{version}' was not found.");
        }
    }

    private static PluginVersionRecord ReadPluginVersion(SqliteDataReader reader) => new()
    {
        PluginId = reader.GetString(0),
        Version = Version.Parse(reader.GetString(1)),
        ContractVersion = reader.GetString(2),
        EntryAssembly = reader.GetString(3),
        EntryType = reader.GetString(4),
        ExecutionMode = Enum.Parse<ExecutionMode>(reader.GetString(5)),
        ArtifactHash = reader.GetString(6),
        State = Enum.Parse<PluginLifecycleState>(reader.GetString(7)),
        InstalledAt = DbTimestamp.Parse(reader.GetString(8)),
        ValidatedAt = reader.IsDBNull(9) ? null : DbTimestamp.Parse(reader.GetString(9)),
        ValidationError = reader.IsDBNull(10) ? null : reader.GetString(10),
        ManifestJson = reader.IsDBNull(11) ? null : reader.GetString(11),
        StagingPath = reader.IsDBNull(12) ? null : reader.GetString(12),
        ArtifactPath = reader.IsDBNull(13) ? null : reader.GetString(13),
        UncleanUnloadReason = reader.IsDBNull(14) ? null : reader.GetString(14),
    };
}

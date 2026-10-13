namespace Scheduler.Infrastructure.Persistence;

/// <summary>
/// The ordered set of registry schema migrations. Version 1 is the initial
/// schema from <see cref="SchemaDefinitions" />; new versions append.
/// </summary>
public static class SchemaMigrations
{
    public static IReadOnlyList<Migration> All { get; } =
    [
        new Migration(
            Version: 1,
            Name: "initial-registry-schema",
            Sql: string.Join(Environment.NewLine, SchemaDefinitions.All)),
        new Migration(
            Version: 2,
            Name: "plugin-version-package-columns",
            Sql: """
                ALTER TABLE plugin_versions ADD COLUMN manifest_json TEXT;
                ALTER TABLE plugin_versions ADD COLUMN staging_path TEXT;
                ALTER TABLE plugin_versions ADD COLUMN artifact_path TEXT;
                """),
        new Migration(
            Version: 3,
            Name: "plugin-version-unclean-unload",
            Sql: """
                ALTER TABLE plugin_versions ADD COLUMN unclean_unload_reason TEXT;
                """),
        new Migration(
            Version: 4,
            Name: "observability",
            Sql: string.Join(
                Environment.NewLine,
                "ALTER TABLE executions ADD COLUMN correlation_id TEXT;",
                SchemaDefinitions.ExecutionRejections,
                SchemaDefinitions.ScheduleEvents,
                SchemaDefinitions.ReconciliationRuns)),
        new Migration(
            Version: 5,
            Name: "secrets-and-idempotency",
            Sql: string.Join(
                Environment.NewLine,
                SchemaDefinitions.SecretGrants,
                SchemaDefinitions.Idempotency)),
    ];

    public static int LatestVersion => All[^1].Version;
}

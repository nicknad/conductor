namespace Scheduler.Infrastructure.Persistence;

/// <summary>
/// DDL for the platform's own logical data areas. Quartz manages its own
/// tables (created from the upstream SQLite script); this schema owns the
/// plugin registry, job registry, execution store, audit log, and the
/// durable operation records used for reconciliation.
/// </summary>
public static class SchemaDefinitions
{
    /// <summary>Plugin identities, versions, artifact hashes, lifecycle state.</summary>
    public const string PluginRegistry = """
        CREATE TABLE IF NOT EXISTS plugin_versions (
            plugin_id        TEXT NOT NULL,
            version          TEXT NOT NULL,
            contract_version TEXT NOT NULL,
            entry_assembly   TEXT NOT NULL,
            entry_type       TEXT NOT NULL,
            execution_mode   TEXT NOT NULL,
            artifact_hash    TEXT NOT NULL,
            state            TEXT NOT NULL,
            installed_at     TEXT NOT NULL,
            validated_at     TEXT,
            validation_error TEXT,
            PRIMARY KEY (plugin_id, version)
        );
        """;

    /// <summary>The atomically published desired active version per plugin.</summary>
    public const string PluginActivation = """
        CREATE TABLE IF NOT EXISTS plugin_activation (
            plugin_id    TEXT PRIMARY KEY,
            version      TEXT NOT NULL,
            activated_at TEXT NOT NULL,
            activated_by TEXT NOT NULL
        );
        """;

    /// <summary>Job definitions, schedules, parameters, revisions.</summary>
    public const string JobRegistry = """
        CREATE TABLE IF NOT EXISTS jobs (
            job_id             TEXT PRIMARY KEY,
            plugin_id          TEXT NOT NULL,
            plugin_version     TEXT NOT NULL,
            enabled            INTEGER NOT NULL,
            schedule           TEXT NOT NULL,
            parameters         TEXT NOT NULL,
            config_revision    INTEGER NOT NULL,
            concurrency_policy TEXT NOT NULL,
            timeout_ms         INTEGER NOT NULL,
            retry_policy       TEXT NOT NULL,
            misfire_policy     TEXT NOT NULL,
            secret_references  TEXT NOT NULL,
            execution_mode     TEXT NOT NULL,
            updated_at         TEXT NOT NULL
        );
        """;

    /// <summary>Durable run status, attempts, timestamps, results.</summary>
    public const string ExecutionStore = """
        CREATE TABLE IF NOT EXISTS executions (
            execution_id       TEXT PRIMARY KEY,
            job_id             TEXT NOT NULL,
            plugin_id          TEXT NOT NULL,
            plugin_version     TEXT NOT NULL,
            config_revision    INTEGER NOT NULL,
            attempt            INTEGER NOT NULL,
            status             TEXT NOT NULL,
            scheduled_at       TEXT NOT NULL,
            started_at         TEXT,
            ended_at           TEXT,
            result_summary     TEXT,
            cancellation_reason TEXT
        );
        """;

    /// <summary>Who performed which action and when.</summary>
    public const string AuditLog = """
        CREATE TABLE IF NOT EXISTS audit_log (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            actor     TEXT NOT NULL,
            action    TEXT NOT NULL,
            target    TEXT NOT NULL,
            details   TEXT
        );
        """;

    /// <summary>
    /// Durable operation records (transactional outbox) tracking changes that
    /// still need to be applied to Quartz or completed after a crash.
    /// </summary>
    public const string Operations = """
        CREATE TABLE IF NOT EXISTS operations (
            operation_id TEXT PRIMARY KEY,
            kind         TEXT NOT NULL,
            payload      TEXT NOT NULL,
            state        TEXT NOT NULL,
            created_at   TEXT NOT NULL,
            updated_at   TEXT NOT NULL
        );
        """;

    /// <summary>Durable records of dispatches that were not admitted, with the reason.</summary>
    public const string ExecutionRejections = """
        CREATE TABLE IF NOT EXISTS execution_rejections (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp      TEXT NOT NULL,
            job_id         TEXT NOT NULL,
            plugin_id      TEXT,
            reason         TEXT NOT NULL,
            correlation_id TEXT NOT NULL,
            details        TEXT
        );
        """;

    /// <summary>Durable records of scheduled fires, misses, and skips observed from Quartz.</summary>
    public const string ScheduleEvents = """
        CREATE TABLE IF NOT EXISTS schedule_events (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp      TEXT NOT NULL,
            job_id         TEXT NOT NULL,
            event_kind     TEXT NOT NULL,
            misfire_policy TEXT
        );
        """;

    /// <summary>Durable history of reconciliation sweeps and their outcomes.</summary>
    public const string ReconciliationRuns = """
        CREATE TABLE IF NOT EXISTS reconciliation_runs (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp    TEXT NOT NULL,
            completed    INTEGER NOT NULL,
            rolled_back  INTEGER NOT NULL,
            synchronized INTEGER NOT NULL,
            error_count  INTEGER NOT NULL,
            succeeded    INTEGER NOT NULL
        );
        """;

    /// <summary>
    /// Durable secret grants: which plugin (optionally which job) may resolve a
    /// reference. An empty <c>job_id</c> is a plugin-wide grant. Values never
    /// appear here; they live only in the encrypted store.
    /// </summary>
    public const string SecretGrants = """
        CREATE TABLE IF NOT EXISTS secret_grants (
            plugin_id        TEXT NOT NULL,
            job_id           TEXT NOT NULL,
            secret_reference TEXT NOT NULL,
            granted_by       TEXT NOT NULL,
            granted_at       TEXT NOT NULL,
            PRIMARY KEY (plugin_id, job_id, secret_reference)
        );
        """;

    /// <summary>Durable operation-id → result mapping for idempotent lifecycle requests.</summary>
    public const string Idempotency = """
        CREATE TABLE IF NOT EXISTS idempotency (
            operation_id TEXT PRIMARY KEY,
            action       TEXT NOT NULL,
            target       TEXT NOT NULL,
            result       TEXT,
            created_at   TEXT NOT NULL,
            updated_at   TEXT NOT NULL
        );
        """;

    public static readonly string[] All =
    [
        PluginRegistry,
        PluginActivation,
        JobRegistry,
        ExecutionStore,
        AuditLog,
        Operations,
    ];
}

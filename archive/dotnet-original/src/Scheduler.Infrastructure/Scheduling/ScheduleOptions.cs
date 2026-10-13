namespace Scheduler.Infrastructure.Scheduling;

/// <summary>
/// Tuning for the Quartz projection: scheduler identity, trigger grouping, the
/// SQLite connection settings shared with the registry, and the reconciliation
/// cadence. All values are explicit configuration, never environment guesses.
/// </summary>
public sealed class ScheduleOptions
{
    /// <summary>Logical scheduler name; also the Quartz instance name.</summary>
    public string SchedulerName { get; init; } = "scheduler";

    /// <summary>Quartz group every job key and trigger key belongs to.</summary>
    public string JobGroup { get; init; } = "jobs";

    /// <summary>Busy timeout applied to every Quartz connection (milliseconds).</summary>
    public int BusyTimeoutMilliseconds { get; init; } = 5000;

    /// <summary>How late a fire time may be before Quartz treats it as a misfire.</summary>
    public TimeSpan MisfireThreshold { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>How often the background reconciler repairs drift.</summary>
    public TimeSpan ReconciliationInterval { get; init; } = TimeSpan.FromMinutes(1);

    /// <summary>Quartz worker thread count.</summary>
    public int ThreadPoolSize { get; init; } = 8;

    /// <summary>
    /// Uses the durable ADO.NET SQLite job store when true; the RAM store
    /// (trigger semantics only) when false, primarily for tests.
    /// </summary>
    public bool UsePersistentStore { get; init; } = true;
}

/// <summary>The string-only job-data keys carried on every Quartz job and trigger.</summary>
public static class ScheduleJobData
{
    public const string JobId = "jobId";
    public const string PluginId = "pluginId";
    public const string Version = "version";
    public const string Revision = "revision";
}

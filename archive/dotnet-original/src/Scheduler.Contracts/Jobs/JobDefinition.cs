using Scheduler.Contracts.Execution;

namespace Scheduler.Contracts.Jobs;

/// <summary>
/// Declarative description of a schedulable job provided by a plugin version.
/// All values are serializable data; no plugin object instances are persisted.
/// </summary>
public sealed record JobDefinition
{
    public required string JobId { get; init; }

    public required string PluginId { get; init; }

    public required Version PluginVersion { get; init; }

    /// <summary>Whether scheduling this job is currently permitted.</summary>
    public bool Enabled { get; init; } = true;

    /// <summary>Trigger specification: cron, fixed interval, or one-shot.</summary>
    public required ScheduleSpec Schedule { get; init; }

    /// <summary>Validated, versioned JSON configuration as key/value data.</summary>
    public IReadOnlyDictionary<string, string?> Parameters { get; init; } =
        new Dictionary<string, string?>();

    /// <summary>Whether overlapping executions of this job are allowed.</summary>
    public ConcurrencyPolicy ConcurrencyPolicy { get; init; } = ConcurrencyPolicy.DisallowOverlap;

    /// <summary>Maximum execution duration before the job is timed out.</summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromMinutes(30);

    /// <summary>Bounded retry configuration.</summary>
    public RetryPolicy RetryPolicy { get; init; } = new();

    /// <summary>Behavior when a scheduled fire time is missed.</summary>
    public MisfirePolicy MisfirePolicy { get; init; } = MisfirePolicy.FireOnce;

    /// <summary>Secret identifiers this job is allowed to request. References only, never values.</summary>
    public IReadOnlyCollection<string> SecretReferences { get; init; } = [];

    /// <summary>How this job executes: in-process or in a worker process.</summary>
    public ExecutionMode ExecutionMode { get; init; } = ExecutionMode.InProcess;

    /// <summary>
    /// Returns validation errors for this definition. An empty list means the
    /// definition can be persisted and scheduled.
    /// </summary>
    public IReadOnlyList<string> Validate()
    {
        List<string> errors = [];

        if (string.IsNullOrWhiteSpace(JobId))
        {
            errors.Add("JobId must not be empty.");
        }

        if (string.IsNullOrWhiteSpace(PluginId))
        {
            errors.Add("PluginId must not be empty.");
        }

        errors.AddRange(Schedule.Validate());

        if (Timeout <= TimeSpan.Zero)
        {
            errors.Add("Timeout must be positive.");
        }

        errors.AddRange(RetryPolicy.Validate());

        foreach (string reference in SecretReferences)
        {
            if (string.IsNullOrWhiteSpace(reference))
            {
                errors.Add("SecretReferences must not contain empty entries.");
                break;
            }
        }

        return errors;
    }
}

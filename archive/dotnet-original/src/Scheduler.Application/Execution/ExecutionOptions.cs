namespace Scheduler.Application.Execution;

/// <summary>
/// Execution-plane limits. The global limit is the platform-wide cap on
/// concurrent executions; the drain timeout bounds how long deactivation waits
/// for running executions under the <see cref="DrainPolicy.Wait" /> policy.
/// </summary>
public sealed class ExecutionOptions
{
    public int GlobalConcurrencyLimit { get; init; } = 8;

    public TimeSpan DrainTimeout { get; init; } = TimeSpan.FromMinutes(1);

    /// <summary>How running executions are treated when a version is retired.</summary>
    public DrainPolicy DrainPolicy { get; init; } = DrainPolicy.Wait;
}

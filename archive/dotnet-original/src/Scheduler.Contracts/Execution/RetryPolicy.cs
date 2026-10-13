namespace Scheduler.Contracts.Execution;

/// <summary>
/// Bounded retry configuration for a job. Data only; evaluation is a host concern.
/// </summary>
public sealed record RetryPolicy
{
    /// <summary>Total attempt limit including the first attempt. Must be at least 1.</summary>
    public int MaxAttempts { get; init; } = 3;

    /// <summary>Delay before the first retry.</summary>
    public TimeSpan InitialDelay { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>Multiplier applied to the previous delay for each subsequent retry.</summary>
    public double BackoffMultiplier { get; init; } = 2.0;

    /// <summary>Upper bound for any single retry delay.</summary>
    public TimeSpan MaxDelay { get; init; } = TimeSpan.FromMinutes(5);

    public IReadOnlyList<string> Validate()
    {
        List<string> errors = [];

        if (MaxAttempts < 1)
        {
            errors.Add("MaxAttempts must be at least 1.");
        }

        if (InitialDelay < TimeSpan.Zero)
        {
            errors.Add("InitialDelay must not be negative.");
        }

        if (BackoffMultiplier < 1.0)
        {
            errors.Add("BackoffMultiplier must be at least 1.");
        }

        if (MaxDelay < InitialDelay)
        {
            errors.Add("MaxDelay must not be smaller than InitialDelay.");
        }

        return errors;
    }
}

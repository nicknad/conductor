namespace Scheduler.Contracts.Jobs;

/// <summary>
/// A trigger specification. Exactly one of <see cref="Cron" />,
/// <see cref="Interval" />, or <see cref="OneShotAt" /> must be set.
/// </summary>
public sealed record ScheduleSpec
{
    /// <summary>Cron expression (5 to 7 fields).</summary>
    public string? Cron { get; init; }

    /// <summary>Fixed interval between fire times.</summary>
    public TimeSpan? Interval { get; init; }

    /// <summary>A single fire time.</summary>
    public DateTimeOffset? OneShotAt { get; init; }

    public static ScheduleSpec FromCron(string cron) => new() { Cron = cron };

    public static ScheduleSpec FromInterval(TimeSpan interval) => new() { Interval = interval };

    public static ScheduleSpec FromOneShot(DateTimeOffset at) => new() { OneShotAt = at };

    /// <summary>Returns validation errors. An empty list means the spec is usable.</summary>
    public IReadOnlyList<string> Validate()
    {
        List<string> errors = [];

        int set = 0;
        set += Cron is not null ? 1 : 0;
        set += Interval is not null ? 1 : 0;
        set += OneShotAt is not null ? 1 : 0;

        if (set == 0)
        {
            errors.Add("Exactly one of cron, interval, or oneShotAt must be set.");
        }

        if (set > 1)
        {
            errors.Add("Only one of cron, interval, or oneShotAt may be set.");
        }

        if (Cron is not null)
        {
            string[] fields = Cron.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length is < 5 or > 7)
            {
                errors.Add($"Cron must have 5 to 7 fields, found {fields.Length}.");
            }
        }

        if (Interval is not null && Interval.Value <= TimeSpan.Zero)
        {
            errors.Add("Interval must be positive.");
        }

        return errors;
    }
}

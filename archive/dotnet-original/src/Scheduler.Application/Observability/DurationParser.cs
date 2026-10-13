using System.Globalization;

namespace Scheduler.Application.Observability;

/// <summary>
/// Parses and formats the compact duration form used by observability query
/// windows and `--since` filters (for example `90s`, `30m`, `24h`, `7d`).
/// </summary>
public static class DurationParser
{
    public static bool TryParse(string value, out TimeSpan duration)
    {
        duration = TimeSpan.Zero;
        if (value.Length < 2)
        {
            return false;
        }

        if (!double.TryParse(value[..^1], NumberStyles.Float, CultureInfo.InvariantCulture, out double amount)
            || amount <= 0)
        {
            return false;
        }

        duration = value[^1] switch
        {
            's' => TimeSpan.FromSeconds(amount),
            'm' => TimeSpan.FromMinutes(amount),
            'h' => TimeSpan.FromHours(amount),
            'd' => TimeSpan.FromDays(amount),
            _ => TimeSpan.Zero,
        };

        return duration > TimeSpan.Zero;
    }

    public static string ToQueryValue(TimeSpan duration) =>
        ((long)duration.TotalSeconds).ToString(CultureInfo.InvariantCulture) + "s";
}

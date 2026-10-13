using System.Globalization;

namespace Scheduler.Infrastructure.Persistence;

/// <summary>Round-trip (ISO 8601) helpers for persisted timestamps.</summary>
internal static class DbTimestamp
{
    private const string RoundTripFormat = "o";

    public static string Format(DateTimeOffset value) =>
        value.ToUniversalTime().ToString(RoundTripFormat, CultureInfo.InvariantCulture);

    public static DateTimeOffset Parse(string value) =>
        DateTimeOffset.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
}

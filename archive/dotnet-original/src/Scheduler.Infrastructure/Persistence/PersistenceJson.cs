using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Scheduler.Infrastructure.Persistence;

/// <summary>JSON settings used for persisted value objects (schedules, policies, parameters).</summary>
internal static class PersistenceJson
{
    public static JsonSerializerOptions Options { get; } = CreateOptions();

    private static JsonSerializerOptions CreateOptions()
    {
        JsonSerializerOptions options = new();
        options.Converters.Add(new JsonStringEnumConverter());
        options.Converters.Add(new TimeSpanJsonConverter());
        return options;
    }
}

/// <summary>Serializes <see cref="TimeSpan" /> in round-trip constant ("c") form.</summary>
internal sealed class TimeSpanJsonConverter : JsonConverter<TimeSpan>
{
    public override TimeSpan Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value is null
            ? default
            : TimeSpan.ParseExact(value, "c", CultureInfo.InvariantCulture);
    }

    public override void Write(Utf8JsonWriter writer, TimeSpan value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        writer.WriteStringValue(value.ToString("c", CultureInfo.InvariantCulture));
    }
}

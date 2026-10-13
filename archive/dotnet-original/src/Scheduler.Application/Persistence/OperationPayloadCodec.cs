using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Scheduler.Application.Persistence;

/// <summary>
/// Serialization for durable operation payloads. The wire format is internal, but
/// every payload carries a version so a host can refuse (rather than misread)
/// records written by a newer build.
/// </summary>
public static class OperationPayloadCodec
{
    public static JsonSerializerOptions Options { get; } = CreateOptions();

    public static string Serialize<T>(T payload) => JsonSerializer.Serialize(payload, Options);

    /// <exception cref="InvalidOperationException">The payload could not be read.</exception>
    public static T Deserialize<T>(string payload)
        where T : notnull =>
        JsonSerializer.Deserialize<T>(payload, Options)
            ?? throw new InvalidOperationException(
                $"An operation payload could not be deserialized as {typeof(T).Name}.");

    private static JsonSerializerOptions CreateOptions()
    {
        JsonSerializerOptions options = new(JsonSerializerDefaults.Web);
        options.Converters.Add(new JsonStringEnumConverter());
        options.Converters.Add(new OperationTimeSpanConverter());
        return options;
    }
}

/// <summary>Round-trips <see cref="TimeSpan" /> in round-trip constant ("c") form.</summary>
internal sealed class OperationTimeSpanConverter : JsonConverter<TimeSpan>
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

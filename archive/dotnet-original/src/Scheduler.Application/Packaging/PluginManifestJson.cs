using System.Text.Json;
using Scheduler.Contracts.Execution;

namespace Scheduler.Application.Packaging;

/// <summary>Result of parsing a package manifest.</summary>
public sealed record PluginManifestParseResult(PluginManifest? Manifest, IReadOnlyList<string> Errors)
{
    public bool IsValid => Manifest is not null;
}

/// <summary>
/// Reads and writes the manifest's canonical form. The canonical form is compact
/// UTF-8 JSON with ordinal-sorted keys and fixed enum wire values; it is the
/// exact byte sequence the package signature covers.
/// </summary>
public static class PluginManifestJson
{
    private static readonly string[] CanonicalPropertyOrder =
    [
        "artifactHash",
        "capabilities",
        "contractVersion",
        "dependencies",
        "entryAssembly",
        "entryType",
        "executionMode",
        "id",
        "version",
    ];

    public static PluginManifestParseResult Parse(ReadOnlySpan<byte> utf8)
    {
        List<string> errors = [];

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(utf8.ToArray());
        }
        catch (JsonException exception)
        {
            return new PluginManifestParseResult(null, [$"Manifest is not valid JSON: {exception.Message}"]);
        }

        using (document)
        {
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return new PluginManifestParseResult(null, ["Manifest must be a JSON object."]);
            }

            string id = ReadRequiredString(root, "id", errors);
            Version? version = ReadRequiredVersion(root, "version", errors);
            Version? contractVersion = ReadRequiredVersion(root, "contractVersion", errors);
            string entryAssembly = ReadRequiredString(root, "entryAssembly", errors);
            string entryType = ReadRequiredString(root, "entryType", errors);
            ExecutionMode? executionMode = ReadRequiredExecutionMode(root, "executionMode", errors);
            string artifactHash = ReadRequiredString(root, "artifactHash", errors);
            IReadOnlyList<string> capabilities = ReadStringArray(root, "capabilities", errors);
            IReadOnlyList<string> dependencies = ReadStringArray(root, "dependencies", errors);

            if (!string.IsNullOrEmpty(artifactHash) && !IsWellFormedArtifactHash(artifactHash))
            {
                errors.Add("artifactHash must be formatted as 'sha256:' followed by 64 lowercase hex characters.");
            }

            if (errors.Count > 0)
            {
                return new PluginManifestParseResult(null, errors);
            }

            return new PluginManifestParseResult(
                new PluginManifest
                {
                    Id = id,
                    Version = version!,
                    ContractVersion = contractVersion!,
                    EntryAssembly = entryAssembly,
                    EntryType = entryType,
                    ExecutionMode = executionMode!.Value,
                    Capabilities = capabilities,
                    Dependencies = dependencies,
                    ArtifactHash = artifactHash,
                },
                []);
        }
    }

    public static byte[] ToCanonicalUtf8(PluginManifest manifest)
    {
        ArgumentNullException.ThrowIfNull(manifest);

        using MemoryStream stream = new();
        using (Utf8JsonWriter writer = new(stream, new JsonWriterOptions { Indented = false }))
        {
            writer.WriteStartObject();
            foreach (string property in CanonicalPropertyOrder)
            {
                switch (property)
                {
                    case "artifactHash":
                        writer.WriteString(property, manifest.ArtifactHash);
                        break;
                    case "capabilities":
                        WriteStringArray(writer, property, manifest.Capabilities);
                        break;
                    case "contractVersion":
                        writer.WriteString(property, manifest.ContractVersion.ToString());
                        break;
                    case "dependencies":
                        WriteStringArray(writer, property, manifest.Dependencies);
                        break;
                    case "entryAssembly":
                        writer.WriteString(property, manifest.EntryAssembly);
                        break;
                    case "entryType":
                        writer.WriteString(property, manifest.EntryType);
                        break;
                    case "executionMode":
                        writer.WriteString(property, ToWire(manifest.ExecutionMode));
                        break;
                    case "id":
                        writer.WriteString(property, manifest.Id);
                        break;
                    case "version":
                        writer.WriteString(property, manifest.Version.ToString());
                        break;
                    default:
                        throw new InvalidOperationException($"Unexpected canonical property '{property}'.");
                }
            }

            writer.WriteEndObject();
        }

        return stream.ToArray();
    }

    /// <summary>Maps an execution mode to its documented manifest wire value.</summary>
    public static string ToWire(ExecutionMode mode) => mode switch
    {
        ExecutionMode.InProcess => "in-process",
        ExecutionMode.Worker => "worker",
        _ => throw new ArgumentOutOfRangeException(nameof(mode), mode, "Unknown execution mode."),
    };

    private static bool TryParseExecutionMode(string wire, out ExecutionMode mode)
    {
        switch (wire)
        {
            case "in-process":
                mode = ExecutionMode.InProcess;
                return true;
            case "worker":
                mode = ExecutionMode.Worker;
                return true;
            default:
                mode = default;
                return false;
        }
    }

    private static string ReadRequiredString(JsonElement root, string name, List<string> errors)
    {
        if (!root.TryGetProperty(name, out JsonElement element) || element.ValueKind != JsonValueKind.String)
        {
            errors.Add($"Manifest field '{name}' is required and must be a string.");
            return string.Empty;
        }

        string value = element.GetString() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(value))
        {
            errors.Add($"Manifest field '{name}' must not be empty.");
        }

        return value;
    }

    private static Version? ReadRequiredVersion(JsonElement root, string name, List<string> errors)
    {
        string value = ReadRequiredString(root, name, errors);
        if (string.IsNullOrEmpty(value))
        {
            return null;
        }

        if (!Version.TryParse(value, out Version? version))
        {
            errors.Add($"Manifest field '{name}' must be a valid version, found '{value}'.");
            return null;
        }

        return version;
    }

    private static ExecutionMode? ReadRequiredExecutionMode(JsonElement root, string name, List<string> errors)
    {
        string value = ReadRequiredString(root, name, errors);
        if (string.IsNullOrEmpty(value))
        {
            return null;
        }

        if (!TryParseExecutionMode(value, out ExecutionMode mode))
        {
            errors.Add($"Manifest field '{name}' must be 'in-process' or 'worker', found '{value}'.");
            return null;
        }

        return mode;
    }

    private static List<string> ReadStringArray(JsonElement root, string name, List<string> errors)
    {
        if (!root.TryGetProperty(name, out JsonElement element))
        {
            return [];
        }

        if (element.ValueKind != JsonValueKind.Array)
        {
            errors.Add($"Manifest field '{name}' must be an array of strings.");
            return [];
        }

        List<string> values = [];
        foreach (JsonElement item in element.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(item.GetString()))
            {
                errors.Add($"Manifest field '{name}' must contain only non-empty strings.");
                return [];
            }

            values.Add(item.GetString()!);
        }

        return values;
    }

    private static void WriteStringArray(Utf8JsonWriter writer, string property, IReadOnlyList<string> values)
    {
        writer.WriteStartArray(property);
        foreach (string value in values)
        {
            writer.WriteStringValue(value);
        }

        writer.WriteEndArray();
    }

    private static bool IsWellFormedArtifactHash(string value)
    {
        if (!value.StartsWith(CanonicalPackageDigest.Prefix, StringComparison.Ordinal))
        {
            return false;
        }

        string hex = value[CanonicalPackageDigest.Prefix.Length..];
        if (hex.Length != 64)
        {
            return false;
        }

        return hex.All(c => c is (>= '0' and <= '9') or (>= 'a' and <= 'f'));
    }
}

using System.Text.Json;

namespace Scheduler.Application.Packaging;

/// <summary>Reads the detached <c>signature.json</c> from a package.</summary>
public static class PackageSignatureJson
{
    public const int SupportedFormatVersion = 1;

    public static PackageSignatureParseResult Parse(ReadOnlySpan<byte> utf8)
    {
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(utf8.ToArray());
        }
        catch (JsonException exception)
        {
            return new PackageSignatureParseResult(null, [$"Signature is not valid JSON: {exception.Message}"]);
        }

        using (document)
        {
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return new PackageSignatureParseResult(null, ["Signature must be a JSON object."]);
            }

            if (!TryReadFormatVersion(root, out int formatVersion, out string? formatError))
            {
                return new PackageSignatureParseResult(null, [formatError!]);
            }

            if (!TryReadAlgorithm(root, out PackageSignatureAlgorithm algorithm, out string? algorithmError))
            {
                return new PackageSignatureParseResult(null, [algorithmError!]);
            }

            if (!TryReadSignature(root, out byte[] signature, out string? signatureError))
            {
                return new PackageSignatureParseResult(null, [signatureError!]);
            }

            return new PackageSignatureParseResult(new PackageSignature(formatVersion, algorithm, signature), []);
        }
    }

    public static bool TryParseAlgorithm(string wire, out PackageSignatureAlgorithm algorithm)
    {
        switch (wire)
        {
            case "RS256":
                algorithm = PackageSignatureAlgorithm.Rs256;
                return true;
            case "ES256":
                algorithm = PackageSignatureAlgorithm.Es256;
                return true;
            default:
                algorithm = default;
                return false;
        }
    }

    private static bool TryReadFormatVersion(JsonElement root, out int formatVersion, out string? error)
    {
        formatVersion = 0;
        if (!root.TryGetProperty("formatVersion", out JsonElement element)
            || element.ValueKind != JsonValueKind.Number
            || !element.TryGetInt32(out int value))
        {
            error = "Signature field 'formatVersion' is required and must be an integer.";
            return false;
        }

        if (value != SupportedFormatVersion)
        {
            error = $"Signature formatVersion '{value}' is not supported (expected {SupportedFormatVersion}).";
            return false;
        }

        formatVersion = value;
        error = null;
        return true;
    }

    private static bool TryReadAlgorithm(JsonElement root, out PackageSignatureAlgorithm algorithm, out string? error)
    {
        algorithm = default;
        if (!root.TryGetProperty("algorithm", out JsonElement element) || element.ValueKind != JsonValueKind.String)
        {
            error = "Signature field 'algorithm' is required and must be a string.";
            return false;
        }

        string wire = element.GetString() ?? string.Empty;
        if (!TryParseAlgorithm(wire, out algorithm))
        {
            error = $"Signature algorithm '{wire}' is not supported.";
            return false;
        }

        error = null;
        return true;
    }

    private static bool TryReadSignature(JsonElement root, out byte[] signature, out string? error)
    {
        signature = [];
        if (!root.TryGetProperty("signature", out JsonElement element) || element.ValueKind != JsonValueKind.String)
        {
            error = "Signature field 'signature' is required and must be a base64 string.";
            return false;
        }

        string base64 = element.GetString() ?? string.Empty;
        if (base64.Length == 0)
        {
            error = "Signature field 'signature' must not be empty.";
            return false;
        }

        try
        {
            signature = Convert.FromBase64String(base64);
        }
        catch (FormatException)
        {
            error = "Signature field 'signature' is not valid base64.";
            return false;
        }

        error = null;
        return true;
    }
}

/// <summary>Result of parsing <c>signature.json</c>.</summary>
public sealed record PackageSignatureParseResult(PackageSignature? Signature, IReadOnlyList<string> Errors)
{
    public bool IsValid => Signature is not null;
}

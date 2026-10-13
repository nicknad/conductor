using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Scheduler.Application.Packaging;
using Scheduler.Contracts.Execution;

const string DefaultPluginId = "example-reporting";
const string DefaultPluginVersion = "1.0.0";
const string DefaultEntryType = "Scheduler.Example.Plugin.ReportingPlugin";
const string DefaultEntryAssembly = "Scheduler.Example.Plugin.dll";
const string ContractVersion = "1.0";
const string PrivateKeyFileName = "package-signing.key";
const string PublicKeyFileName = "package-signing.pub.pem";

string workingDirectory = Directory.GetCurrentDirectory();
string pluginId = ReadOption(args, "--id", DefaultPluginId);
string pluginVersion = ReadOption(args, "--version", DefaultPluginVersion);
string entryType = ReadOption(args, "--entry-type", DefaultEntryType);
string pluginPath = ReadOption(args, "--plugin", Path.Combine(AppContext.BaseDirectory, DefaultEntryAssembly));
string keysDirectory = ReadOption(args, "--keys", Path.Combine(workingDirectory, "keys"));
string outputPath = ReadOption(
    args,
    "--output",
    Path.Combine(workingDirectory, "example-package", $"{pluginId}.{pluginVersion}.zip"));

if (!File.Exists(pluginPath))
{
    Console.Error.WriteLine($"error: plugin assembly '{pluginPath}' was not found.");
    return 1;
}

Directory.CreateDirectory(keysDirectory);
string privateKeyPath = Path.Combine(keysDirectory, PrivateKeyFileName);
string publicKeyPath = Path.Combine(keysDirectory, PublicKeyFileName);

using RSA key = LoadOrCreateKey(privateKeyPath, publicKeyPath);
File.WriteAllText(publicKeyPath, key.ExportSubjectPublicKeyInfoPem());

string entryAssembly = Path.GetFileName(pluginPath);
IReadOnlyList<(string Path, byte[] Content)> payload = BuildPayload(pluginPath, entryAssembly);

byte[] digest = CanonicalPackageDigest.ComputeHash(Entries(payload));
PluginManifest manifest = new()
{
    Id = pluginId,
    Version = Version.Parse(pluginVersion),
    ContractVersion = Version.Parse(ContractVersion),
    EntryAssembly = entryAssembly,
    EntryType = entryType,
    ExecutionMode = ExecutionMode.InProcess,
    Capabilities = ["logging"],
    Dependencies = [],
    ArtifactHash = CanonicalPackageDigest.Format(digest),
};

byte[] canonicalManifest = PluginManifestJson.ToCanonicalUtf8(manifest);
byte[] signature = key.SignData(
    [.. canonicalManifest, .. digest],
    HashAlgorithmName.SHA256,
    RSASignaturePadding.Pkcs1);
byte[] signatureJson = JsonSerializer.SerializeToUtf8Bytes(new
{
    formatVersion = PackageSignatureJson.SupportedFormatVersion,
    algorithm = "RS256",
    signature = Convert.ToBase64String(signature),
});

byte[] package = Zip(
[
    .. payload,
    (PackageLayout.ManifestFileName, canonicalManifest),
    (PackageLayout.SignatureFileName, signatureJson),
]);

string? outputDirectory = Path.GetDirectoryName(outputPath);
if (!string.IsNullOrEmpty(outputDirectory))
{
    Directory.CreateDirectory(outputDirectory);
}

File.WriteAllBytes(outputPath, package);

Console.WriteLine($"package  {outputPath}");
Console.WriteLine($"public   {publicKeyPath}");
Console.WriteLine($"plugin   {pluginId} {pluginVersion} ({entryType})");
return 0;

static string ReadOption(string[] args, string name, string fallback)
{
    for (int index = 0; index < args.Length - 1; index++)
    {
        if (string.Equals(args[index], name, StringComparison.Ordinal))
        {
            return args[index + 1];
        }
    }

    return fallback;
}

static RSA LoadOrCreateKey(string privateKeyPath, string publicKeyPath)
{
    if (File.Exists(privateKeyPath))
    {
        RSA existing = RSA.Create();
        existing.ImportFromPem(File.ReadAllText(privateKeyPath));
        return existing;
    }

    RSA created = RSA.Create(2048);
    File.WriteAllText(privateKeyPath, created.ExportPkcs8PrivateKeyPem());
    File.WriteAllText(publicKeyPath, created.ExportSubjectPublicKeyInfoPem());
    return created;
}

static IReadOnlyList<(string Path, byte[] Content)> BuildPayload(string pluginPath, string entryAssembly)
{
    List<(string Path, byte[] Content)> payload = [(entryAssembly, File.ReadAllBytes(pluginPath))];

    string dependencyPath = Path.ChangeExtension(pluginPath, ".deps.json");
    if (File.Exists(dependencyPath))
    {
        payload.Add((Path.GetFileName(dependencyPath), File.ReadAllBytes(dependencyPath)));
    }

    return payload;
}

static IReadOnlyList<PackageEntry> Entries(IReadOnlyList<(string Path, byte[] Content)> files) =>
    files
        .Select(file => new PackageEntry(
            file.Path,
            file.Content.Length,
            Convert.ToHexStringLower(SHA256.HashData(file.Content))))
        .ToArray();

static byte[] Zip(IReadOnlyList<(string Path, byte[] Content)> entries)
{
    using MemoryStream stream = new();
    using (ZipArchive archive = new(stream, ZipArchiveMode.Create, leaveOpen: true))
    {
        foreach ((string path, byte[] content) in entries)
        {
            ZipArchiveEntry entry = archive.CreateEntry(path, CompressionLevel.Optimal);
            using Stream target = entry.Open();
            target.Write(content);
        }
    }

    return stream.ToArray();
}

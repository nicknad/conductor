using System.IO.Abstractions;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Scheduler.Application.Secrets;
using Scheduler.Infrastructure.Packaging;

namespace Scheduler.Infrastructure.Secrets;

/// <summary>
/// A file-backed <see cref="ISecretValueStore" />. Each reference's value is
/// encrypted independently with AES-256-GCM (nonce + tag + ciphertext). The key
/// is a separate file outside every writable root. Only values are secret;
/// references are stored in the clear for enumeration.
/// </summary>
public sealed class FileSecretValueStore : ISecretValueStore
{
    private const int KeySizeBytes = 32;
    private const int NonceSizeBytes = 12;
    private const int TagSizeBytes = 16;
    private const string EnvelopeExtension = ".secret";

    private static readonly JsonSerializerOptions JsonOptions = new();

    private readonly IFileSystem _fileSystem;
    private readonly string _storeRoot;
    private readonly string _keyPath;
    private readonly object _keyLock = new();
    private byte[]? _key;

    public FileSecretValueStore(SecretStoreOptions options, IFileSystem fileSystem)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(fileSystem);

        _fileSystem = fileSystem;
        _storeRoot = PackagingPaths.Resolve(options.StoreRoot, options.BaseDirectory, fileSystem);
        _keyPath = PackagingPaths.Resolve(options.KeyPath, options.BaseDirectory, fileSystem);
    }

    public Task<string?> GetAsync(string secretReference, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(secretReference);
        cancellationToken.ThrowIfCancellationRequested();

        string path = GetPath(secretReference);
        if (!_fileSystem.File.Exists(path))
        {
            return Task.FromResult<string?>(null);
        }

        byte[] bytes = _fileSystem.File.ReadAllBytes(path);
        Envelope envelope = JsonSerializer.Deserialize<Envelope>(bytes, JsonOptions)
            ?? throw new InvalidOperationException(
                $"Secret store entry for '{secretReference}' could not be read.");

        if (!string.Equals(envelope.Reference, secretReference, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"Secret store entry for '{secretReference}' is corrupted or was tampered with.");
        }

        byte[] plaintext = Decrypt(GetOrCreateKey(), envelope, secretReference);
        return Task.FromResult<string?>(Encoding.UTF8.GetString(plaintext));
    }

    public Task SetAsync(string secretReference, string value, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(secretReference);
        ArgumentNullException.ThrowIfNull(value);
        cancellationToken.ThrowIfCancellationRequested();

        Envelope envelope = Encrypt(GetOrCreateKey(), secretReference, value);
        WriteAtomic(GetPath(secretReference), JsonSerializer.SerializeToUtf8Bytes(envelope, JsonOptions));
        return Task.CompletedTask;
    }

    public Task RemoveAsync(string secretReference, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(secretReference);
        cancellationToken.ThrowIfCancellationRequested();

        string path = GetPath(secretReference);
        if (_fileSystem.File.Exists(path))
        {
            _fileSystem.File.Delete(path);
        }

        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<string>> ListReferencesAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!_fileSystem.Directory.Exists(_storeRoot))
        {
            return Task.FromResult<IReadOnlyList<string>>([]);
        }

        List<string> references = [];
        foreach (string file in _fileSystem.Directory.EnumerateFiles(_storeRoot, "*" + EnvelopeExtension))
        {
            byte[] bytes = _fileSystem.File.ReadAllBytes(file);
            Envelope? envelope = JsonSerializer.Deserialize<Envelope>(bytes, JsonOptions);
            if (envelope is not null)
            {
                references.Add(envelope.Reference);
            }
        }

        references.Sort(StringComparer.Ordinal);
        return Task.FromResult<IReadOnlyList<string>>(references);
    }

    private string GetPath(string secretReference) =>
        _fileSystem.Path.Combine(_storeRoot, HashReference(secretReference) + EnvelopeExtension);

    private static string HashReference(string secretReference) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(secretReference)));

    private byte[] GetOrCreateKey()
    {
        if (_key is not null)
        {
            return _key;
        }

        lock (_keyLock)
        {
            if (_key is not null)
            {
                return _key;
            }

            _key = _fileSystem.File.Exists(_keyPath) ? ReadKey() : CreateKey();
            return _key;
        }
    }

    private byte[] ReadKey()
    {
        byte[] key = _fileSystem.File.ReadAllBytes(_keyPath);
        if (key.Length != KeySizeBytes)
        {
            throw new InvalidOperationException(
                $"Secret store key '{_keyPath}' must be {KeySizeBytes} bytes.");
        }

        return key;
    }

    private byte[] CreateKey()
    {
        byte[] created = RandomNumberGenerator.GetBytes(KeySizeBytes);
        WriteAtomic(_keyPath, created);
        RestrictKeyPermissions();
        return created;
    }

    private void WriteAtomic(string path, byte[] bytes)
    {
        string? directory = _fileSystem.Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory))
        {
            _fileSystem.Directory.CreateDirectory(directory);
        }

        string temporary = path + ".tmp-" + Guid.NewGuid().ToString("N");
        _fileSystem.File.WriteAllBytes(temporary, bytes);
        _fileSystem.File.Move(temporary, path, overwrite: true);
    }

    private void RestrictKeyPermissions()
    {
        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS() || OperatingSystem.IsFreeBSD())
        {
            File.SetUnixFileMode(_keyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }

    private static Envelope Encrypt(byte[] key, string reference, string value)
    {
        byte[] plaintext = Encoding.UTF8.GetBytes(value);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
        byte[] tag = new byte[TagSizeBytes];
        byte[] associatedData = Encoding.UTF8.GetBytes(reference);

        using AesGcm aes = new(key, TagSizeBytes);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

        return new Envelope(
            reference,
            Convert.ToBase64String(nonce),
            Convert.ToBase64String(tag),
            Convert.ToBase64String(ciphertext));
    }

    private static byte[] Decrypt(byte[] key, Envelope envelope, string reference)
    {
        byte[] nonce = Convert.FromBase64String(envelope.Iv);
        byte[] tag = Convert.FromBase64String(envelope.Tag);
        byte[] ciphertext = Convert.FromBase64String(envelope.Data);
        byte[] plaintext = new byte[ciphertext.Length];
        byte[] associatedData = Encoding.UTF8.GetBytes(reference);

        using AesGcm aes = new(key, TagSizeBytes);
        aes.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
        return plaintext;
    }

    private sealed record Envelope(
        [property: JsonPropertyName("reference")] string Reference,
        [property: JsonPropertyName("iv")] string Iv,
        [property: JsonPropertyName("tag")] string Tag,
        [property: JsonPropertyName("data")] string Data);
}

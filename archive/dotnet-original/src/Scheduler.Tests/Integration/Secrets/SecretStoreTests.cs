using System.IO.Abstractions;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Scheduler.Infrastructure.Secrets;

namespace Scheduler.Tests.Integration.Secrets;

public sealed class SecretStoreTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task RoundTripsAndNeverStoresTheValueInCleartext()
    {
        string root = CreateTempDirectory();
        try
        {
            FileSystem fileSystem = new();
            SecretStoreOptions options = new()
            {
                StoreRoot = Path.Combine(root, "secrets"),
                KeyPath = Path.Combine(root, "store.key"),
                BaseDirectory = root,
            };
            FileSecretValueStore store = new(options, fileSystem);

            await store.SetAsync("db-password", "hunter2-value", Ct);

            Assert.Equal("hunter2-value", await store.GetAsync("db-password", Ct));
            Assert.Contains("db-password", await store.ListReferencesAsync(Ct));

            string entry = Directory.GetFiles(options.StoreRoot).Single();
            Assert.DoesNotContain("hunter2-value", File.ReadAllText(entry), StringComparison.Ordinal);
            Assert.Equal(32, new FileInfo(options.KeyPath).Length);

            await store.RemoveAsync("db-password", Ct);
            Assert.Null(await store.GetAsync("db-password", Ct));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void GuardAcceptsAKeyOutsideWritableRoots()
    {
        FileSystem fileSystem = new();
        SecretStoreOptions options = new()
        {
            StoreRoot = "data/secrets",
            KeyPath = "keys/store.key",
            BaseDirectory = "C:/host",
            WritableRoots = ["data", "logs"],
        };

        SecretKeyPathGuard.EnsureOutsideWritableRoots(options, fileSystem);
    }

    [Fact]
    public void GuardRejectsAKeyInsideAWritableRoot()
    {
        FileSystem fileSystem = new();
        SecretStoreOptions options = new()
        {
            StoreRoot = "data/secrets",
            KeyPath = "data/store.key",
            BaseDirectory = "C:/host",
            WritableRoots = ["data", "logs"],
        };

        Assert.Throws<InvalidOperationException>(
            () => SecretKeyPathGuard.EnsureOutsideWritableRoots(options, fileSystem));
    }

    [Fact]
    public async Task TamperedEnvelopeReferenceIsRejected()
    {
        string root = CreateTempDirectory();
        try
        {
            FileSystem fileSystem = new();
            SecretStoreOptions options = new()
            {
                StoreRoot = Path.Combine(root, "secrets"),
                KeyPath = Path.Combine(root, "store.key"),
                BaseDirectory = root,
            };
            FileSecretValueStore store = new(options, fileSystem);
            await store.SetAsync("a", "value-a", Ct);

            string entry = Directory.GetFiles(options.StoreRoot).Single();
            string tampered = File.ReadAllText(entry).Replace("\"reference\":\"a\"", "\"reference\":\"b\"", StringComparison.Ordinal);
            File.WriteAllText(entry, tampered);

            await Assert.ThrowsAsync<InvalidOperationException>(() => store.GetAsync("a", Ct));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task TamperedCiphertextFailsAuthentication()
    {
        string root = CreateTempDirectory();
        try
        {
            FileSystem fileSystem = new();
            SecretStoreOptions options = new()
            {
                StoreRoot = Path.Combine(root, "secrets"),
                KeyPath = Path.Combine(root, "store.key"),
                BaseDirectory = root,
            };
            FileSecretValueStore store = new(options, fileSystem);
            await store.SetAsync("a", "value-a", Ct);

            string entry = Directory.GetFiles(options.StoreRoot).Single();
            JsonNode envelope = JsonNode.Parse(File.ReadAllText(entry))!;
            byte[] ciphertext = Convert.FromBase64String(envelope["data"]!.GetValue<string>());
            ciphertext[0] ^= 0xFF;
            envelope["data"] = Convert.ToBase64String(ciphertext);
            File.WriteAllText(entry, envelope.ToJsonString());

            await Assert.ThrowsAnyAsync<CryptographicException>(() => store.GetAsync("a", Ct));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static string CreateTempDirectory()
    {
        string directory = Path.Combine(Path.GetTempPath(), "jobscheduler-secrets", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        return directory;
    }
}

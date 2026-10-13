namespace Scheduler.Infrastructure.Secrets;

/// <summary>
/// Explicit locations for the encrypted secret store. Relative paths resolve
/// against <see cref="BaseDirectory" /> (the host content root). The key file
/// must live outside every writable root.
/// </summary>
public sealed class SecretStoreOptions
{
    public required string StoreRoot { get; init; }

    /// <summary>Path to the store's AES key file; must be outside every writable root.</summary>
    public required string KeyPath { get; init; }

    public string? BaseDirectory { get; init; }

    public IReadOnlyList<string> WritableRoots { get; init; } = [];
}

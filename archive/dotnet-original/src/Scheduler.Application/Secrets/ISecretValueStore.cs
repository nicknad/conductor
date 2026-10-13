namespace Scheduler.Application.Secrets;

/// <summary>
/// The host-owned encrypted store of secret values, addressed by opaque
/// references. Values never enter the registry database, the artifact store,
/// logs, or the contract; only references and metadata cross this boundary.
/// </summary>
public interface ISecretValueStore
{
    /// <summary>Returns the value for <paramref name="secretReference" />, or <c>null</c> when absent.</summary>
    Task<string?> GetAsync(string secretReference, CancellationToken cancellationToken = default);

    /// <summary>Creates or replaces the value for <paramref name="secretReference" />.</summary>
    Task SetAsync(string secretReference, string value, CancellationToken cancellationToken = default);

    /// <summary>Removes the value for <paramref name="secretReference" />; missing is not an error.</summary>
    Task RemoveAsync(string secretReference, CancellationToken cancellationToken = default);

    /// <summary>Lists stored references (never values).</summary>
    Task<IReadOnlyList<string>> ListReferencesAsync(CancellationToken cancellationToken = default);
}

namespace Scheduler.Application.Secrets;

/// <summary>
/// The durable grant of a secret reference to a plugin (optionally narrowed to a
/// single job). An empty <see cref="JobId" /> is a plugin-wide grant. Grants are
/// the registry's authorization truth; values live only in the encrypted store.
/// </summary>
public sealed record SecretGrant
{
    public required string PluginId { get; init; }

    /// <summary>The job the grant is narrowed to, or <c>null</c> for a plugin-wide grant.</summary>
    public string? JobId { get; init; }

    public required string SecretReference { get; init; }

    public required string GrantedBy { get; init; }

    public required DateTimeOffset GrantedAt { get; init; }
}

/// <summary>Persistence port for durable secret grants.</summary>
public interface ISecretGrantRepository
{
    /// <summary>Creates or updates a grant. Idempotent for the same (plugin, job, reference).</summary>
    Task GrantAsync(SecretGrant grant, CancellationToken cancellationToken = default);

    /// <summary>Removes a grant; returns whether a row existed.</summary>
    Task<bool> RevokeAsync(
        string pluginId,
        string? jobId,
        string secretReference,
        CancellationToken cancellationToken = default);

    /// <summary>Lists the grants for one plugin (both plugin-wide and per-job).</summary>
    Task<IReadOnlyList<SecretGrant>> ListAsync(string pluginId, CancellationToken cancellationToken = default);
}

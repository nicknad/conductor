using Scheduler.Application.Persistence;

namespace Scheduler.Application.Secrets;

/// <summary>
/// Administrative use cases for secrets: changing grants and setting, rotating,
/// or removing stored values. All operations are audited as metadata — a
/// reference and the change — and never accept or emit a value except through
/// the store's write path.
/// </summary>
public sealed class SecretAdminService
{
    private readonly IRegistryUnitOfWorkFactory _unitOfWorkFactory;
    private readonly ISecretValueStore _store;
    private readonly IAuditWriter _audit;
    private readonly TimeProvider _timeProvider;

    public SecretAdminService(
        IRegistryUnitOfWorkFactory unitOfWorkFactory,
        ISecretValueStore store,
        IAuditWriter audit,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(unitOfWorkFactory);
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(audit);
        ArgumentNullException.ThrowIfNull(timeProvider);

        _unitOfWorkFactory = unitOfWorkFactory;
        _store = store;
        _audit = audit;
        _timeProvider = timeProvider;
    }

    public async Task GrantAsync(
        string pluginId,
        string? jobId,
        string secretReference,
        string actor,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pluginId);
        ArgumentException.ThrowIfNullOrWhiteSpace(secretReference);
        ArgumentException.ThrowIfNullOrWhiteSpace(actor);

        SecretGrant grant = new()
        {
            PluginId = pluginId,
            JobId = string.IsNullOrWhiteSpace(jobId) ? null : jobId,
            SecretReference = secretReference,
            GrantedBy = actor,
            GrantedAt = _timeProvider.GetUtcNow(),
        };

        await using IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken);
        await unitOfWork.SecretGrants.GrantAsync(grant, cancellationToken);
        await unitOfWork.CommitAsync(cancellationToken);

        await _audit.RecordAsync(
            actor,
            "secret.grant",
            secretReference,
            Scope(grant),
            CancellationToken.None);
    }

    public async Task<bool> RevokeAsync(
        string pluginId,
        string? jobId,
        string secretReference,
        string actor,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pluginId);
        ArgumentException.ThrowIfNullOrWhiteSpace(secretReference);
        ArgumentException.ThrowIfNullOrWhiteSpace(actor);

        string? normalizedJob = string.IsNullOrWhiteSpace(jobId) ? null : jobId;

        await using IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken);
        bool removed = await unitOfWork.SecretGrants.RevokeAsync(pluginId, normalizedJob, secretReference, cancellationToken);
        await unitOfWork.CommitAsync(cancellationToken);

        await _audit.RecordAsync(
            actor,
            "secret.revoke",
            secretReference,
            $"plugin={pluginId};job={normalizedJob ?? "*"};removed={removed}",
            CancellationToken.None);

        return removed;
    }

    public async Task SetValueAsync(
        string secretReference,
        string value,
        string actor,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(secretReference);
        ArgumentException.ThrowIfNullOrWhiteSpace(actor);
        ArgumentNullException.ThrowIfNull(value);

        await _store.SetAsync(secretReference, value, cancellationToken);
        await _audit.RecordAsync(actor, "secret.set", secretReference, "value updated", CancellationToken.None);
    }

    public async Task RemoveValueAsync(
        string secretReference,
        string actor,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(secretReference);
        ArgumentException.ThrowIfNullOrWhiteSpace(actor);

        await _store.RemoveAsync(secretReference, cancellationToken);
        await _audit.RecordAsync(actor, "secret.remove", secretReference, null, CancellationToken.None);
    }

    public Task<IReadOnlyList<string>> ListReferencesAsync(CancellationToken cancellationToken = default) =>
        _store.ListReferencesAsync(cancellationToken);

    public async Task<IReadOnlyList<SecretGrant>> ListGrantsAsync(
        string pluginId,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pluginId);

        await using IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken);
        return await unitOfWork.SecretGrants.ListAsync(pluginId, cancellationToken);
    }

    private static string Scope(SecretGrant grant) => $"plugin={grant.PluginId};job={grant.JobId ?? "*"}";
}

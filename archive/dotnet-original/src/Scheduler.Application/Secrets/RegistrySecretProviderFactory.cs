using Scheduler.Application.Observability;
using Scheduler.Application.Persistence;
using Scheduler.Contracts.Secrets;

namespace Scheduler.Application.Secrets;

/// <summary>
/// Builds a per-execution provider from the durable grants for the executing
/// plugin/job. Reading the registry here (at the dispatch boundary) is the
/// resolve-at-dispatch point: new executions see the latest grants and values,
/// while already-running executions keep the provider they were given.
/// </summary>
public sealed class RegistrySecretProviderFactory : ISecretProviderFactory
{
    private readonly IRegistryUnitOfWorkFactory _unitOfWorkFactory;
    private readonly ISecretValueStore _store;
    private readonly IAuditWriter _audit;

    public RegistrySecretProviderFactory(
        IRegistryUnitOfWorkFactory unitOfWorkFactory,
        ISecretValueStore store,
        IAuditWriter audit)
    {
        ArgumentNullException.ThrowIfNull(unitOfWorkFactory);
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(audit);

        _unitOfWorkFactory = unitOfWorkFactory;
        _store = store;
        _audit = audit;
    }

    public async Task<ISecretProvider> CreateAsync(
        ExecutionIdentity identity,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(identity);

        await using IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken);
        IReadOnlyList<SecretGrant> grants = await unitOfWork.SecretGrants.ListAsync(identity.PluginId, cancellationToken);

        HashSet<string> granted = new(StringComparer.Ordinal);
        foreach (SecretGrant grant in grants)
        {
            if (grant.JobId is null || string.Equals(grant.JobId, identity.JobId, StringComparison.Ordinal))
            {
                granted.Add(grant.SecretReference);
            }
        }

        return new GrantedSecretProvider(identity, granted, _store, _audit);
    }
}

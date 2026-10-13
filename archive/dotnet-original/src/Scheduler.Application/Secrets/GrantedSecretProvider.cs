using System.Collections.Concurrent;
using Scheduler.Application.Observability;
using Scheduler.Application.Persistence;
using Scheduler.Contracts.Secrets;

namespace Scheduler.Application.Secrets;

/// <summary>
/// An execution-scoped secret provider restricted to the references granted for
/// the executing plugin/job. It is an authorization boundary, not a sandbox.
/// Values acquired by the execution are cached for its lifetime, so a running
/// execution keeps the value it obtained even if the store is rotated; new
/// executions resolve the latest value. Every decision is audited as metadata
/// — never a value.
/// </summary>
public sealed class GrantedSecretProvider : ISecretProvider
{
    private const string Actor = "execution";

    private readonly IReadOnlySet<string> _granted;
    private readonly ISecretValueStore _store;
    private readonly IAuditWriter _audit;
    private readonly ExecutionIdentity _identity;
    private readonly ConcurrentDictionary<string, string> _acquired = new(StringComparer.Ordinal);

    public GrantedSecretProvider(
        ExecutionIdentity identity,
        IReadOnlySet<string> granted,
        ISecretValueStore store,
        IAuditWriter audit)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(granted);
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(audit);

        _identity = identity;
        _granted = granted;
        _store = store;
        _audit = audit;
    }

    public async Task<string> ResolveAsync(string secretReference, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(secretReference);

        if (_acquired.TryGetValue(secretReference, out string? held))
        {
            return held;
        }

        if (!_granted.Contains(secretReference))
        {
            await AuditAsync("secret.access.denied", secretReference, "not-granted", cancellationToken);
            throw new SecretNotAuthorizedException(secretReference);
        }

        string? value = await _store.GetAsync(secretReference, cancellationToken);
        if (value is null)
        {
            await AuditAsync("secret.access.denied", secretReference, "unavailable", cancellationToken);
            throw new SecretNotAuthorizedException(secretReference);
        }

        await AuditAsync("secret.access.allowed", secretReference, null, cancellationToken);
        _acquired[secretReference] = value;
        return value;
    }

    private Task AuditAsync(string action, string reference, string? reason, CancellationToken cancellationToken)
    {
        string details = $"plugin={_identity.PluginId};job={_identity.JobId};execution={_identity.ExecutionId:D}"
            + (reason is null ? string.Empty : $";reason={reason}");

        return _audit.RecordAsync(Actor, action, reference, details, cancellationToken);
    }
}

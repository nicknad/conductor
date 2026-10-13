using Scheduler.Application.Observability;
using Scheduler.Contracts.Secrets;

namespace Scheduler.Application.Secrets;

/// <summary>
/// Creates the execution-scoped <see cref="ISecretProvider" /> handed to a job,
/// restricted to the references granted for that execution's plugin and job.
/// The backend is a singleton, so the provider must be built per execution —
/// exactly like the execution-scoped logger.
/// </summary>
public interface ISecretProviderFactory
{
    Task<ISecretProvider> CreateAsync(ExecutionIdentity identity, CancellationToken cancellationToken = default);
}

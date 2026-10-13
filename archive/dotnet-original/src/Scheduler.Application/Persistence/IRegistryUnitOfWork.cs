using Scheduler.Application.Observability;
using Scheduler.Application.Secrets;
using Scheduler.Application.Security;

namespace Scheduler.Application.Persistence;

/// <summary>
/// A single SQLite transaction over the registry's logical data areas. Registry
/// writes and their operation record are committed together; a crash before
/// commit leaves neither visible.
/// </summary>
public interface IRegistryUnitOfWork : IAsyncDisposable
{
    IPluginRepository Plugins { get; }

    IJobRepository Jobs { get; }

    IExecutionRepository Executions { get; }

    IOperationRepository Operations { get; }

    IAuditLogRepository Audit { get; }

    IExecutionRejectionRepository Rejections { get; }

    IScheduleEventRepository ScheduleEvents { get; }

    IReconciliationRunRepository ReconciliationRuns { get; }

    ISecretGrantRepository SecretGrants { get; }

    IIdempotencyStore Idempotency { get; }

    Task CommitAsync(CancellationToken cancellationToken = default);

    Task RollbackAsync(CancellationToken cancellationToken = default);
}

/// <summary>Creates <see cref="IRegistryUnitOfWork" /> instances over the registry database.</summary>
public interface IRegistryUnitOfWorkFactory
{
    Task<IRegistryUnitOfWork> BeginAsync(CancellationToken cancellationToken = default);
}

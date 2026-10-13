namespace Scheduler.Application.Persistence;

/// <summary>
/// Writes each audit event in its own committed transaction, stamping the
/// timestamp from the injected <see cref="TimeProvider" />. Details are never
/// secret values.
/// </summary>
public sealed class AuditWriter : IAuditWriter
{
    private readonly IRegistryUnitOfWorkFactory _unitOfWorkFactory;
    private readonly TimeProvider _timeProvider;

    public AuditWriter(IRegistryUnitOfWorkFactory unitOfWorkFactory, TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(unitOfWorkFactory);
        ArgumentNullException.ThrowIfNull(timeProvider);

        _unitOfWorkFactory = unitOfWorkFactory;
        _timeProvider = timeProvider;
    }

    public async Task RecordAsync(
        string actor,
        string action,
        string target,
        string? details = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(actor);
        ArgumentException.ThrowIfNullOrWhiteSpace(action);
        ArgumentException.ThrowIfNullOrWhiteSpace(target);

        await using IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken);
        await unitOfWork.Audit.WriteAsync(
            new AuditEntry
            {
                Timestamp = _timeProvider.GetUtcNow(),
                Actor = actor,
                Action = action,
                Target = target,
                Details = details,
            },
            cancellationToken);
        await unitOfWork.CommitAsync(cancellationToken);
    }
}

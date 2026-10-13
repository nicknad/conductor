using Scheduler.Application.Persistence;

namespace Scheduler.Application.Observability;

/// <summary>
/// Records a not-admitted dispatch in its own committed transaction, stamping the
/// host clock and generating a correlation id. Never records secret values.
/// </summary>
public sealed class ExecutionRejectionWriter : IExecutionRejectionWriter
{
    private readonly IRegistryUnitOfWorkFactory _unitOfWorkFactory;
    private readonly TimeProvider _timeProvider;

    public ExecutionRejectionWriter(IRegistryUnitOfWorkFactory unitOfWorkFactory, TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(unitOfWorkFactory);
        ArgumentNullException.ThrowIfNull(timeProvider);

        _unitOfWorkFactory = unitOfWorkFactory;
        _timeProvider = timeProvider;
    }

    public async Task RecordAsync(
        string jobId,
        string? pluginId,
        ExecutionRejectionReason reason,
        string? details = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(jobId);

        await using IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken);
        await unitOfWork.Rejections.RecordAsync(
            new ExecutionRejection
            {
                Timestamp = _timeProvider.GetUtcNow(),
                JobId = jobId,
                PluginId = pluginId,
                Reason = reason,
                CorrelationId = Guid.NewGuid().ToString("N"),
                Details = details,
            },
            cancellationToken);
        await unitOfWork.CommitAsync(cancellationToken);
    }
}

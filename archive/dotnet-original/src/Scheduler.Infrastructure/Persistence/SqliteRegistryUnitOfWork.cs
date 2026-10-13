using Microsoft.Data.Sqlite;
using Scheduler.Application.Observability;
using Scheduler.Application.Persistence;
using Scheduler.Application.Secrets;
using Scheduler.Application.Security;

namespace Scheduler.Infrastructure.Persistence;

/// <summary>
/// A single registry transaction. Exposes the data-area repositories over one
/// connection and commits them together; regardless of <see cref="CommitAsync" />,
/// disposing rolls back anything not committed.
/// </summary>
internal sealed partial class SqliteRegistryUnitOfWork :
    IRegistryUnitOfWork,
    IPluginRepository,
    IJobRepository,
    IExecutionRepository,
    IOperationRepository,
    IAuditLogRepository,
    IExecutionRejectionRepository,
    IScheduleEventRepository,
    IReconciliationRunRepository,
    ISecretGrantRepository,
    IIdempotencyStore
{
    private readonly ISqliteConnectionFactory _connectionFactory;
    private SqliteConnection? _connection;
    private SqliteTransaction? _transaction;
    private bool _completed;

    public SqliteRegistryUnitOfWork(ISqliteConnectionFactory connectionFactory)
    {
        ArgumentNullException.ThrowIfNull(connectionFactory);
        _connectionFactory = connectionFactory;
    }

    public IPluginRepository Plugins => this;

    public IJobRepository Jobs => this;

    public IExecutionRepository Executions => this;

    public IOperationRepository Operations => this;

    public IAuditLogRepository Audit => this;

    public IExecutionRejectionRepository Rejections => this;

    public IScheduleEventRepository ScheduleEvents => this;

    public IReconciliationRunRepository ReconciliationRuns => this;

    public ISecretGrantRepository SecretGrants => this;

    public IIdempotencyStore Idempotency => this;

    public async Task CommitAsync(CancellationToken cancellationToken = default)
    {
        EnsureActive();
        await _transaction!.CommitAsync(cancellationToken);
        _completed = true;
    }

    public async Task RollbackAsync(CancellationToken cancellationToken = default)
    {
        EnsureActive();
        await _transaction!.RollbackAsync(cancellationToken);
        _completed = true;
    }

    public async ValueTask DisposeAsync()
    {
        if (_transaction is not null)
        {
            await _transaction.DisposeAsync();
        }

        if (_connection is not null)
        {
            await _connection.DisposeAsync();
        }

        GC.SuppressFinalize(this);
    }

    internal static async Task<SqliteRegistryUnitOfWork> BeginAsync(
        ISqliteConnectionFactory connectionFactory,
        CancellationToken cancellationToken)
    {
        SqliteRegistryUnitOfWork unitOfWork = new(connectionFactory);
        try
        {
            await unitOfWork.InitializeAsync(cancellationToken);
            return unitOfWork;
        }
        catch
        {
            await unitOfWork.DisposeAsync();
            throw;
        }
    }

    private async Task InitializeAsync(CancellationToken cancellationToken)
    {
        _connection = await _connectionFactory.OpenConnectionAsync(cancellationToken);
        _transaction = (SqliteTransaction)await _connection.BeginTransactionAsync(cancellationToken);
    }

    private SqliteCommand CreateCommand(string commandText)
    {
        SqliteCommand command = _connection!.CreateCommand();
        command.Transaction = _transaction;
        command.CommandText = commandText;
        return command;
    }

    private void EnsureActive()
    {
        if (_completed)
        {
            throw new InvalidOperationException("The unit of work has already completed.");
        }
    }
}

using Scheduler.Application.Persistence;

namespace Scheduler.Infrastructure.Persistence;

/// <summary>Creates registry transactions over the configured SQLite database.</summary>
public sealed class SqliteRegistryUnitOfWorkFactory : IRegistryUnitOfWorkFactory
{
    private readonly ISqliteConnectionFactory _connectionFactory;

    public SqliteRegistryUnitOfWorkFactory(ISqliteConnectionFactory connectionFactory)
    {
        ArgumentNullException.ThrowIfNull(connectionFactory);
        _connectionFactory = connectionFactory;
    }

    public async Task<IRegistryUnitOfWork> BeginAsync(CancellationToken cancellationToken = default)
    {
        return await SqliteRegistryUnitOfWork.BeginAsync(_connectionFactory, cancellationToken);
    }
}

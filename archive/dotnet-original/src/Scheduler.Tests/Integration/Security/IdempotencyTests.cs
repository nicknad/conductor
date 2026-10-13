using Scheduler.Application.Persistence;
using Scheduler.Application.PluginManagement;
using Scheduler.Application.Security;
using Scheduler.Tests.Integration;

namespace Scheduler.Tests.Integration.Security;

public sealed class IdempotencyTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task ReplayReturnsTheSameResultWithoutReExecuting()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(Ct);
        LifecycleRequestCoordinator coordinator = new(database.UnitOfWorkFactory, TimeProvider.System);

        Guid operationId = Guid.NewGuid();
        int calls = 0;
        Func<CancellationToken, Task<PluginOperation>> operation = _ =>
        {
            calls++;
            return Task.FromResult(Succeeded(operationId));
        };

        PluginOperation first = await coordinator.RunAsync(operationId, "activate", "plugin-1:1.0.0", operation, Ct);
        PluginOperation second = await coordinator.RunAsync(operationId, "activate", "plugin-1:1.0.0", operation, Ct);

        Assert.Equal(1, calls);
        Assert.Equal(first.OperationId, second.OperationId);
        Assert.Equal(PluginOperationStatus.Succeeded, second.Status);
    }

    [Fact]
    public async Task DifferentOperationIdsExecuteIndependently()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(Ct);
        LifecycleRequestCoordinator coordinator = new(database.UnitOfWorkFactory, TimeProvider.System);

        int calls = 0;
        Func<CancellationToken, Task<PluginOperation>> operation = token =>
        {
            calls++;
            return Task.FromResult(Succeeded(Guid.NewGuid()));
        };

        await coordinator.RunAsync(Guid.NewGuid(), "activate", "plugin-1:1.0.0", operation, Ct);
        await coordinator.RunAsync(Guid.NewGuid(), "activate", "plugin-1:1.0.0", operation, Ct);

        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task ReplayWhileInFlightIsRejected()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(Ct);
        LifecycleRequestCoordinator coordinator = new(database.UnitOfWorkFactory, TimeProvider.System);

        Guid operationId = Guid.NewGuid();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        await using (IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(Ct))
        {
            await unitOfWork.Idempotency.TryBeginAsync(
                new IdempotencyRecord
                {
                    OperationId = operationId,
                    Action = "activate",
                    Target = "plugin-1:1.0.0",
                    Result = null,
                    CreatedAt = now,
                    UpdatedAt = now,
                },
                Ct);
            await unitOfWork.CommitAsync(Ct);
        }

        await Assert.ThrowsAsync<IdempotentOperationInProgressException>(
            () => coordinator.RunAsync(
                operationId,
                "activate",
                "plugin-1:1.0.0",
                _ => Task.FromResult(Succeeded(operationId)),
                Ct));
    }

    [Fact]
    public async Task ReplayWithDifferentActionOrTargetIsRejected()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(Ct);
        LifecycleRequestCoordinator coordinator = new(database.UnitOfWorkFactory, TimeProvider.System);

        Guid operationId = Guid.NewGuid();
        await coordinator.RunAsync(
            operationId,
            "activate",
            "plugin-1:1.0.0",
            _ => Task.FromResult(Succeeded(operationId)),
            Ct);

        await Assert.ThrowsAsync<IdempotentOperationConflictException>(
            () => coordinator.RunAsync(
                operationId,
                "remove",
                "plugin-1",
                _ => Task.FromResult(Succeeded(operationId)),
                Ct));
    }

    [Fact]
    public async Task RecordedFailureIsReplayedWithoutReExecuting()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(Ct);
        LifecycleRequestCoordinator coordinator = new(database.UnitOfWorkFactory, TimeProvider.System);

        Guid operationId = Guid.NewGuid();
        int calls = 0;
        Func<CancellationToken, Task<PluginOperation>> operation = _ =>
        {
            calls++;
            throw new InvalidOperationException("boom");
        };

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => coordinator.RunAsync(operationId, "activate", "plugin-1:1.0.0", operation, Ct));

        PluginOperation replayed = await coordinator.RunAsync(operationId, "activate", "plugin-1:1.0.0", operation, Ct);

        Assert.Equal(1, calls);
        Assert.Equal(PluginOperationStatus.Failed, replayed.Status);
    }

    [Fact]
    public async Task RecoverInterruptedCompletesInFlightRecords()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(Ct);
        LifecycleRequestCoordinator coordinator = new(database.UnitOfWorkFactory, TimeProvider.System);

        Guid operationId = Guid.NewGuid();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        await using (IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(Ct))
        {
            await unitOfWork.Idempotency.TryBeginAsync(
                new IdempotencyRecord
                {
                    OperationId = operationId,
                    Action = "activate",
                    Target = "plugin-1:1.0.0",
                    Result = null,
                    CreatedAt = now,
                    UpdatedAt = now,
                },
                Ct);
            await unitOfWork.CommitAsync(Ct);
        }

        Assert.Equal(1, await coordinator.RecoverInterruptedAsync(Ct));

        int calls = 0;
        PluginOperation replayed = await coordinator.RunAsync(
            operationId,
            "activate",
            "plugin-1:1.0.0",
            _ =>
            {
                calls++;
                return Task.FromResult(Succeeded(operationId));
            },
            Ct);

        Assert.Equal(0, calls);
        Assert.Equal(PluginOperationStatus.Failed, replayed.Status);
    }

    private static PluginOperation Succeeded(Guid operationId) =>
        new(operationId, "plugin-1", new Version(1, 0, 0), PluginOperationStatus.Succeeded);
}

using Scheduler.Application.Persistence;

namespace Scheduler.Tests.Integration;

public sealed class AuditLogRepositoryTests
{
    private static readonly DateTimeOffset Timestamp = new(2026, 5, 6, 7, 8, 9, TimeSpan.Zero);

    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task EntriesRoundTripNewestFirst()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);

        await using (IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken))
        {
            await unitOfWork.Audit.WriteAsync(NewEntry("install", "monthly-report/1.0.0"), CancellationToken);
            await unitOfWork.Audit.WriteAsync(NewEntry("activate", "monthly-report/1.0.0", details: null), CancellationToken);
            await unitOfWork.CommitAsync(CancellationToken);
        }

        await using IRegistryUnitOfWork read = await database.UnitOfWorkFactory.BeginAsync(CancellationToken);
        IReadOnlyList<AuditEntry> entries = await read.Audit.ListAsync(cancellationToken: CancellationToken);

        Assert.Equal(2, entries.Count);
        Assert.Equal("activate", entries[0].Action);
        Assert.Null(entries[0].Details);
        Assert.Equal("install", entries[1].Action);
        Assert.Equal("operator", entries[1].Actor);
        Assert.True(entries[0].Id > entries[1].Id);
    }

    [Fact]
    public async Task ListHonorsLimit()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);

        await using (IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken))
        {
            await unitOfWork.Audit.WriteAsync(NewEntry("install", "a/1.0.0"), CancellationToken);
            await unitOfWork.Audit.WriteAsync(NewEntry("activate", "a/1.0.0"), CancellationToken);
            await unitOfWork.Audit.WriteAsync(NewEntry("deactivate", "a/1.0.0"), CancellationToken);
            await unitOfWork.CommitAsync(CancellationToken);
        }

        await using IRegistryUnitOfWork read = await database.UnitOfWorkFactory.BeginAsync(CancellationToken);
        IReadOnlyList<AuditEntry> entries = await read.Audit.ListAsync(limit: 2, CancellationToken);

        Assert.Equal(2, entries.Count);
        Assert.Equal("deactivate", entries[0].Action);
    }

    private static AuditEntry NewEntry(string action, string target, string? details = "detail") => new()
    {
        Timestamp = Timestamp,
        Actor = "operator",
        Action = action,
        Target = target,
        Details = details,
    };
}

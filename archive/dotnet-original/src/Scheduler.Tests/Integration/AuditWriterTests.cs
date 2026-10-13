using Scheduler.Application.Persistence;

namespace Scheduler.Tests.Integration;

public sealed class AuditWriterTests
{
    private static readonly DateTimeOffset Now = new(2026, 6, 7, 8, 9, 10, TimeSpan.Zero);

    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task RecordPersistsEntryStampedFromProvider()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);

        AuditWriter writer = new(database.UnitOfWorkFactory, new FixedTimeProvider(Now));

        await writer.RecordAsync("operator", "activate", "monthly-report/1.2.0", "manual", CancellationToken);

        await using IRegistryUnitOfWork read = await database.UnitOfWorkFactory.BeginAsync(CancellationToken);
        IReadOnlyList<AuditEntry> entries = await read.Audit.ListAsync(cancellationToken: CancellationToken);

        Assert.Single(entries);
        AuditEntry entry = entries[0];
        Assert.Equal(Now, entry.Timestamp);
        Assert.Equal("operator", entry.Actor);
        Assert.Equal("activate", entry.Action);
        Assert.Equal("monthly-report/1.2.0", entry.Target);
        Assert.Equal("manual", entry.Details);
    }

    [Theory]
    [InlineData("", "action", "target")]
    [InlineData("actor", "", "target")]
    [InlineData("actor", "action", "")]
    public async Task RecordRejectsBlankArguments(string actor, string action, string target)
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);

        AuditWriter writer = new(database.UnitOfWorkFactory, new FixedTimeProvider(Now));

        await Assert.ThrowsAsync<ArgumentException>(
            () => writer.RecordAsync(actor, action, target, cancellationToken: CancellationToken));
    }

    private sealed class FixedTimeProvider : TimeProvider
    {
        private readonly DateTimeOffset _now;

        public FixedTimeProvider(DateTimeOffset now) => _now = now;

        public override DateTimeOffset GetUtcNow() => _now;
    }
}

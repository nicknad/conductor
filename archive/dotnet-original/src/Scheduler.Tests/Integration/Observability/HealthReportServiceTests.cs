using System.IO.Abstractions;
using Scheduler.Application.Observability;
using Scheduler.Application.Persistence;
using Scheduler.Contracts.Execution;
using Scheduler.Infrastructure.Observability;
using Scheduler.Infrastructure.Persistence;

namespace Scheduler.Tests.Integration.Observability;

public sealed class HealthReportServiceTests
{
    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task HealthyWhenDatabaseReachableReconcilerSucceededAndNothingStuck()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);

        FakeReconciliationStatus status = new() { LastSucceededAt = DateTimeOffset.UtcNow };
        SqliteHealthReportService health = new(
            database.ConnectionFactory,
            status,
            new ObservabilityOptions { ExecutionHeartbeat = TimeSpan.FromMinutes(30) },
            TimeProvider.System);

        HealthReport report = await health.GetHealthAsync(CancellationToken);

        Assert.True(report.Healthy);
        Assert.True(report.Database.Healthy);
        Assert.True(report.Reconciler.Healthy);
        Assert.Empty(report.StuckExecutions);
    }

    [Fact]
    public async Task ReportsStuckRunningExecutionAndIsUnhealthy()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);
        DateTimeOffset now = DateTimeOffset.UtcNow;

        Guid stuckId = Guid.NewGuid();
        await using (IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken))
        {
            await unitOfWork.Executions.CreateAsync(
                new ExecutionRecord
                {
                    ExecutionId = stuckId,
                    JobId = "job-1",
                    PluginId = "plugin-1",
                    PluginVersion = new Version(1, 0, 0),
                    ConfigurationRevision = 1,
                    Attempt = 1,
                    Status = JobExecutionStatus.Running,
                    ScheduledAt = now.AddHours(-2),
                    StartedAt = now.AddHours(-2),
                },
                CancellationToken);
            await unitOfWork.CommitAsync(CancellationToken);
        }

        SqliteHealthReportService health = new(
            database.ConnectionFactory,
            new FakeReconciliationStatus { LastSucceededAt = now },
            new ObservabilityOptions { ExecutionHeartbeat = TimeSpan.FromMinutes(30) },
            TimeProvider.System);

        HealthReport report = await health.GetHealthAsync(CancellationToken);

        Assert.False(report.Healthy);
        Assert.Contains(stuckId, report.StuckExecutions);
    }

    [Fact]
    public async Task ReportsReconcilerNotRunYet()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);

        SqliteHealthReportService health = new(
            database.ConnectionFactory,
            new FakeReconciliationStatus(),
            new ObservabilityOptions(),
            TimeProvider.System);

        HealthReport report = await health.GetHealthAsync(CancellationToken);

        Assert.False(report.Healthy);
        Assert.False(report.Reconciler.Healthy);
        Assert.True(report.Database.Healthy);
    }

    [Fact]
    public async Task UnreachableDatabaseIsReportedUnhealthy()
    {
        string directory = Path.Combine(Path.GetTempPath(), "jobscheduler-health", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            // A directory is not a usable SQLite file, so opening the connection fails.
            SqliteConnectionFactory connectionFactory = new(
                new PersistenceOptions { DatabasePath = directory },
                new FileSystem());
            SqliteHealthReportService health = new(
                connectionFactory,
                new FakeReconciliationStatus { LastSucceededAt = DateTimeOffset.UtcNow },
                new ObservabilityOptions(),
                TimeProvider.System);

            HealthReport report = await health.GetHealthAsync(CancellationToken);

            Assert.False(report.Healthy);
            Assert.False(report.Database.Healthy);
            Assert.Empty(report.StuckExecutions);
        }
        finally
        {
            try
            {
                Directory.Delete(directory, recursive: true);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }

    private sealed class FakeReconciliationStatus : IReconciliationStatus
    {
        public DateTimeOffset? LastSucceededAt { get; set; }

        public DateTimeOffset? LastFailedAt { get; set; }

        public int LastErrorCount { get; set; }
    }
}

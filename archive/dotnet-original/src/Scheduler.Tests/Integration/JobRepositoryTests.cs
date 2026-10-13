using Scheduler.Application.Persistence;
using Scheduler.Contracts.Execution;
using Scheduler.Contracts.Jobs;

namespace Scheduler.Tests.Integration;

public sealed class JobRepositoryTests
{
    private static readonly DateTimeOffset UpdatedAt = new(2026, 2, 3, 4, 5, 6, TimeSpan.Zero);

    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task JobRoundTripsAllDefinitionFields()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);

        JobRecord job = NewJob();
        await using (IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken))
        {
            await unitOfWork.Jobs.UpsertAsync(job, CancellationToken);
            await unitOfWork.CommitAsync(CancellationToken);
        }

        await using IRegistryUnitOfWork read = await database.UnitOfWorkFactory.BeginAsync(CancellationToken);
        JobRecord? reloaded = await read.Jobs.GetAsync(job.Definition.JobId, CancellationToken);

        Assert.NotNull(reloaded);
        Assert.Equal(job.ConfigurationRevision, reloaded.ConfigurationRevision);
        Assert.Equal(job.UpdatedAt, reloaded.UpdatedAt);
        Assert.Equal(job.Definition.JobId, reloaded.Definition.JobId);
        Assert.Equal(job.Definition.PluginId, reloaded.Definition.PluginId);
        Assert.Equal(job.Definition.PluginVersion, reloaded.Definition.PluginVersion);
        Assert.Equal(job.Definition.Enabled, reloaded.Definition.Enabled);
        Assert.Equal(job.Definition.Schedule, reloaded.Definition.Schedule);
        Assert.Equal(job.Definition.ConcurrencyPolicy, reloaded.Definition.ConcurrencyPolicy);
        Assert.Equal(job.Definition.Timeout, reloaded.Definition.Timeout);
        Assert.Equal(job.Definition.RetryPolicy, reloaded.Definition.RetryPolicy);
        Assert.Equal(job.Definition.MisfirePolicy, reloaded.Definition.MisfirePolicy);
        Assert.Equal(job.Definition.ExecutionMode, reloaded.Definition.ExecutionMode);
        Assert.Equal(
            job.Definition.SecretReferences.OrderBy(reference => reference, StringComparer.Ordinal),
            reloaded.Definition.SecretReferences.OrderBy(reference => reference, StringComparer.Ordinal));
        Assert.Equal(job.Definition.Parameters.Count, reloaded.Definition.Parameters.Count);
        foreach (KeyValuePair<string, string?> parameter in job.Definition.Parameters)
        {
            Assert.True(reloaded.Definition.Parameters.TryGetValue(parameter.Key, out string? value));
            Assert.Equal(parameter.Value, value);
        }
    }

    [Fact]
    public async Task UpsertReplacesDefinitionAndRevision()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);

        JobRecord job = NewJob();
        await using (IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken))
        {
            await unitOfWork.Jobs.UpsertAsync(job, CancellationToken);
            await unitOfWork.CommitAsync(CancellationToken);
        }

        JobRecord updated = job with
        {
            Definition = job.Definition with { Schedule = ScheduleSpec.FromCron("0 12 * * *") },
            ConfigurationRevision = job.ConfigurationRevision + 1,
        };
        await using (IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken))
        {
            await unitOfWork.Jobs.UpsertAsync(updated, CancellationToken);
            await unitOfWork.CommitAsync(CancellationToken);
        }

        await using IRegistryUnitOfWork read = await database.UnitOfWorkFactory.BeginAsync(CancellationToken);
        JobRecord? reloaded = await read.Jobs.GetAsync(job.Definition.JobId, CancellationToken);

        Assert.NotNull(reloaded);
        Assert.Equal("0 12 * * *", reloaded.Definition.Schedule.Cron);
        Assert.Equal(updated.ConfigurationRevision, reloaded.ConfigurationRevision);
    }

    [Fact]
    public async Task SetEnabledTogglesWithoutChangingRevision()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);

        JobRecord job = NewJob();
        await using (IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken))
        {
            await unitOfWork.Jobs.UpsertAsync(job, CancellationToken);
            await unitOfWork.CommitAsync(CancellationToken);
        }

        await using (IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken))
        {
            await unitOfWork.Jobs.SetEnabledAsync(job.Definition.JobId, enabled: false, UpdatedAt.AddMinutes(1), CancellationToken);
            await unitOfWork.CommitAsync(CancellationToken);
        }

        await using IRegistryUnitOfWork read = await database.UnitOfWorkFactory.BeginAsync(CancellationToken);
        JobRecord? reloaded = await read.Jobs.GetAsync(job.Definition.JobId, CancellationToken);

        Assert.NotNull(reloaded);
        Assert.False(reloaded.Definition.Enabled);
        Assert.Equal(job.ConfigurationRevision, reloaded.ConfigurationRevision);
    }

    [Fact]
    public async Task DeleteRemovesJob()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);

        JobRecord job = NewJob();
        await using (IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken))
        {
            await unitOfWork.Jobs.UpsertAsync(job, CancellationToken);
            await unitOfWork.CommitAsync(CancellationToken);
        }

        await using (IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken))
        {
            Assert.True(await unitOfWork.Jobs.DeleteAsync(job.Definition.JobId, CancellationToken));
            await unitOfWork.CommitAsync(CancellationToken);
        }

        await using IRegistryUnitOfWork read = await database.UnitOfWorkFactory.BeginAsync(CancellationToken);
        Assert.Null(await read.Jobs.GetAsync(job.Definition.JobId, CancellationToken));
    }

    [Fact]
    public async Task ListByPluginReturnsOnlyThatPluginsJobs()
    {
        using SqliteTestDatabase database = new();
        await database.InitializeAsync(CancellationToken);

        JobRecord primary = NewJob();
        JobRecord secondary = NewJob() with
        {
            Definition = NewJob().Definition with { JobId = "secondary-job" },
        };
        JobRecord other = NewJob() with
        {
            Definition = NewJob().Definition with { JobId = "other-job", PluginId = "other-plugin" },
        };

        await using (IRegistryUnitOfWork unitOfWork = await database.UnitOfWorkFactory.BeginAsync(CancellationToken))
        {
            await unitOfWork.Jobs.UpsertAsync(primary, CancellationToken);
            await unitOfWork.Jobs.UpsertAsync(secondary, CancellationToken);
            await unitOfWork.Jobs.UpsertAsync(other, CancellationToken);
            await unitOfWork.CommitAsync(CancellationToken);
        }

        await using IRegistryUnitOfWork read = await database.UnitOfWorkFactory.BeginAsync(CancellationToken);
        IReadOnlyList<JobRecord> jobs = await read.Jobs.ListByPluginAsync("monthly-report", CancellationToken);

        Assert.Equal(2, jobs.Count);
        Assert.All(jobs, job => Assert.Equal("monthly-report", job.Definition.PluginId));
        Assert.Contains(jobs, job => job.Definition.JobId == "monthly-report");
        Assert.Contains(jobs, job => job.Definition.JobId == "secondary-job");
    }

    private static JobRecord NewJob() => new()
    {
        Definition = new JobDefinition
        {
            JobId = "monthly-report",
            PluginId = "monthly-report",
            PluginVersion = new Version(1, 2, 0),
            Enabled = true,
            Schedule = ScheduleSpec.FromInterval(TimeSpan.FromMinutes(15)),
            Parameters = new Dictionary<string, string?>
            {
                ["region"] = "eu-west",
                ["dryRun"] = null,
            },
            ConcurrencyPolicy = ConcurrencyPolicy.AllowParallel,
            Timeout = TimeSpan.FromMinutes(20),
            RetryPolicy = new RetryPolicy
            {
                MaxAttempts = 4,
                InitialDelay = TimeSpan.FromSeconds(3),
                BackoffMultiplier = 1.5,
                MaxDelay = TimeSpan.FromMinutes(2),
            },
            MisfirePolicy = MisfirePolicy.Skip,
            SecretReferences = ["reporting-smtp", "reporting-db"],
            ExecutionMode = ExecutionMode.InProcess,
        },
        ConfigurationRevision = 7,
        UpdatedAt = UpdatedAt,
    };
}

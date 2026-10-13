using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Quartz;
using Quartz.Impl.AdoJobStore;
using Scheduler.Application.Observability;
using Scheduler.Application.Reconciliation;

namespace Scheduler.Infrastructure.Scheduling;

/// <summary>
/// Registers the Quartz scheduler projection and the reconciler. The durable
/// store shares the registry database file with a separate Quartz schema created
/// from Quartz's upstream SQLite script (<c>ProvisionSchema</c>, which provisions
/// only missing objects); triggers converge through the reconciler, so schedule
/// changes never require a host restart.
/// </summary>
public static class SchedulerSchedulingRegistration
{
    public static IServiceCollection AddSchedulerScheduling(
        this IServiceCollection services,
        string databasePath,
        ScheduleOptions options)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
        ArgumentNullException.ThrowIfNull(options);

        services.AddSingleton(options);
        services.AddSingleton<IScheduleStore, QuartzScheduleStore>();
        services.AddSingleton<ScheduleReconciler>();
        services.AddSingleton<IReconciler>(provider => provider.GetRequiredService<ScheduleReconciler>());
        services.AddSingleton<IReconciliationStatus>(provider => provider.GetRequiredService<ScheduleReconciler>());

        services.AddQuartz(builder =>
        {
            builder.ConfigureScheduler(scheduler => scheduler.InstanceName = options.SchedulerName);
            builder.UseDefaultThreadPool(options.ThreadPoolSize);
            builder.AddTriggerListener<ScheduleEventListener>(
                [GroupMatcher<TriggerKey>.GroupEquals(options.JobGroup)]);

            if (options.UsePersistentStore)
            {
                string connectionString = new SqliteConnectionStringBuilder { DataSource = databasePath }.ToString();
                builder.UsePersistentStore(store =>
                {
                    store.UseConnectionProvider(_ => new PragmaApplyingDbProvider(
                        DataSourceOptions.Providers.Sqlite,
                        connectionString,
                        options.BusyTimeoutMilliseconds));
                    store.UseDriverDelegate<SQLiteDelegate>();
                    store.ProvisionSchema();
                    store.ConfigureStore(ado =>
                    {
                        ado.StoreJobDataAsStrings = true;
                        ado.MisfireThreshold = options.MisfireThreshold;
                    });
                });
            }
            else
            {
                builder.UseInMemoryStore(store => store.MisfireThreshold = options.MisfireThreshold);
            }
        });

        services.AddQuartzHostedService(hosted => hosted.WaitForJobsToComplete = true);
        services.AddHostedService<ReconciliationService>();
        return services;
    }
}

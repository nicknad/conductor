using Microsoft.Extensions.DependencyInjection;
using Scheduler.Application.Observability;

namespace Scheduler.Infrastructure.Observability;

/// <summary>
/// Registers the observability surface: the per-execution log store and logger
/// factory, the rejection/schedule-event recorders, and the summary and health
/// read services. All values are durable SQL or per-execution files; nothing is
/// read from in-process meters.
/// </summary>
public static class ObservabilityRegistration
{
    public static IServiceCollection AddSchedulerObservability(
        this IServiceCollection services,
        ObservabilityOptions options)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(options);

        services.AddSingleton(options);
        services.AddSingleton<IExecutionLogStore, FileExecutionLogStore>();
        services.AddSingleton<IExecutionLoggerFactory, ExecutionLoggerFactory>();
        services.AddSingleton<IExecutionRejectionWriter, ExecutionRejectionWriter>();
        services.AddSingleton<IScheduleEventRecorder, ScheduleEventRecorder>();
        services.AddSingleton<IExecutionSummaryService, SqliteExecutionSummaryService>();
        services.AddSingleton<IHealthReportService, SqliteHealthReportService>();
        return services;
    }
}

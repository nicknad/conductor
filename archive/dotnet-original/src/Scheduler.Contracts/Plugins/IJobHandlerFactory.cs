namespace Scheduler.Contracts.Plugins;

/// <summary>
/// Optional companion to <see cref="IJobPlugin" /> for plugins that expose a
/// distinct handler per discovered job. The host resolves the handler for a job
/// by its stable identifier. A plugin that itself implements
/// <see cref="IJobHandler" /> may omit this and serve every job with one handler.
/// </summary>
public interface IJobHandlerFactory
{
    /// <summary>Creates the handler that executes the job with the given id.</summary>
    IJobHandler CreateHandler(string jobId);
}

namespace Scheduler.Application.PluginManagement;

/// <summary>Lifecycle-state helpers shared by the plugin manager and the reconciler.</summary>
public static class PluginLifecycleStateExtensions
{
    /// <summary>
    /// A version that has been promoted to the artifact store and has not been
    /// rejected or failed. Published versions are immutable and always retained
    /// for rollback.
    /// </summary>
    public static bool IsPublished(this PluginLifecycleState state) =>
        state is PluginLifecycleState.Staged
            or PluginLifecycleState.Activating
            or PluginLifecycleState.Active
            or PluginLifecycleState.Draining
            or PluginLifecycleState.Retired;
}

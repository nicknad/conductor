namespace Scheduler.Application.Persistence;

/// <summary>
/// Enforces the durable operation state machine: create → run → succeed / fail /
/// rollback. Terminal states are final; only the transitions below are allowed.
/// </summary>
public static class OperationTransitions
{
    public static bool IsTerminal(OperationState state) =>
        state is OperationState.Succeeded or OperationState.Failed or OperationState.RolledBack;

    public static bool CanTransition(OperationState from, OperationState to) => (from, to) switch
    {
        (OperationState.Pending, OperationState.Running) => true,
        (OperationState.Pending, OperationState.Failed) => true,
        (OperationState.Pending, OperationState.RolledBack) => true,
        (OperationState.Running, OperationState.Succeeded) => true,
        (OperationState.Running, OperationState.Failed) => true,
        (OperationState.Running, OperationState.RolledBack) => true,
        _ => false,
    };

    /// <exception cref="InvalidOperationException">The transition is not permitted.</exception>
    public static void EnsureCanTransition(OperationState from, OperationState to)
    {
        if (!CanTransition(from, to))
        {
            throw new InvalidOperationException(
                $"Operation cannot transition from '{from}' to '{to}'.");
        }
    }
}

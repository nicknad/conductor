using Scheduler.Application.Observability;

namespace Scheduler.Application.Execution;

/// <summary>
/// A dispatch that was not admitted because of the platform's own rules (as
/// opposed to a missing job or an unsupported mode). It carries the structured
/// rejection reason that was also recorded durably.
/// </summary>
public sealed class DispatchRejectedException : InvalidOperationException
{
    public DispatchRejectedException(ExecutionRejectionReason reason, string message)
        : base(message)
    {
        Reason = reason;
    }

    public ExecutionRejectionReason Reason { get; }
}

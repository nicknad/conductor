using Scheduler.Application.Execution;

namespace Scheduler.Tests.Support;

/// <summary>An <see cref="IDispatcher" /> that records dispatches for assertions.</summary>
internal sealed class RecordingDispatcher : IDispatcher
{
    private readonly List<string> _dispatched = [];
    private readonly TaskCompletionSource<string> _first =
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    public IReadOnlyList<string> Dispatched => _dispatched;

    /// <summary>Completes with the first dispatched job id.</summary>
    public Task<string> FirstDispatch => _first.Task;

    public Task<Guid> DispatchAsync(string jobId, CancellationToken cancellationToken = default)
    {
        _dispatched.Add(jobId);
        _first.TrySetResult(jobId);
        return Task.FromResult(Guid.NewGuid());
    }

    public Task<bool> CancelAsync(Guid executionId, string reason, CancellationToken cancellationToken = default) =>
        Task.FromResult(false);
}

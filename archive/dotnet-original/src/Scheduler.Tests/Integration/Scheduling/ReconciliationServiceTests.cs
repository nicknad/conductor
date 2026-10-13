using Microsoft.Extensions.Logging.Abstractions;
using Scheduler.Application.Reconciliation;
using Scheduler.Infrastructure.Scheduling;

namespace Scheduler.Tests.Integration.Scheduling;

public sealed class ReconciliationServiceTests
{
    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task RunsOnceAtStartupAndThenOnThePeriodicSweep()
    {
        CountingReconciler reconciler = new();
        ScheduleOptions options = new() { ReconciliationInterval = TimeSpan.FromMilliseconds(25) };
        using ReconciliationService service = new(
            reconciler,
            options,
            NullLogger<ReconciliationService>.Instance);

        await service.StartAsync(CancellationToken);
        await reconciler.WaitForTwoCallsAsync(TimeSpan.FromSeconds(10), CancellationToken);
        await service.StopAsync(CancellationToken);

        Assert.True(reconciler.CallCount >= 2);
    }

    private sealed class CountingReconciler : IReconciler
    {
        private readonly TaskCompletionSource _reachedTwo = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _calls;

        public int CallCount => Volatile.Read(ref _calls);

        public Task<ReconciliationResult> ReconcileAsync(CancellationToken cancellationToken = default)
        {
            if (Interlocked.Increment(ref _calls) >= 2)
            {
                _reachedTwo.TrySetResult();
            }

            return Task.FromResult(new ReconciliationResult(0, 0, 0, []));
        }

        public async Task WaitForTwoCallsAsync(TimeSpan timeout, CancellationToken cancellationToken)
        {
            await _reachedTwo.Task.WaitAsync(timeout, cancellationToken);
        }
    }
}

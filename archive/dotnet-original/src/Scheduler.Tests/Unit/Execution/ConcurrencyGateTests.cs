using Scheduler.Application.Execution;
using Scheduler.Contracts.Execution;

namespace Scheduler.Tests.Unit.Execution;

public sealed class ConcurrencyGateTests
{
    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task NoOverlapBlocksASecondExecutionOfTheSameJob()
    {
        using ConcurrencyGate gate = new(new ExecutionOptions { GlobalConcurrencyLimit = 8 });

        using IDisposable first = await gate.AcquireAsync("job", ConcurrencyPolicy.DisallowOverlap, CancellationToken);
        Task<IDisposable> second = gate.AcquireAsync("job", ConcurrencyPolicy.DisallowOverlap, CancellationToken);

        await Task.Delay(50, CancellationToken);
        Assert.False(second.IsCompleted);

        first.Dispose();
        using IDisposable secondSlot = await second.WaitAsync(TimeSpan.FromSeconds(2), CancellationToken);
    }

    [Fact]
    public async Task AllowParallelAdmitsTwoExecutionsOfTheSameJob()
    {
        using ConcurrencyGate gate = new(new ExecutionOptions { GlobalConcurrencyLimit = 8 });

        using IDisposable first = await gate.AcquireAsync("job", ConcurrencyPolicy.AllowParallel, CancellationToken);
        Task<IDisposable> second = gate.AcquireAsync("job", ConcurrencyPolicy.AllowParallel, CancellationToken);

        using IDisposable secondSlot = await second.WaitAsync(TimeSpan.FromSeconds(2), CancellationToken);
    }

    [Fact]
    public async Task GlobalLimitBlocksBeyondTheConfiguredConcurrency()
    {
        using ConcurrencyGate gate = new(new ExecutionOptions { GlobalConcurrencyLimit = 1 });

        using IDisposable first = await gate.AcquireAsync("job-1", ConcurrencyPolicy.AllowParallel, CancellationToken);
        Task<IDisposable> second = gate.AcquireAsync("job-2", ConcurrencyPolicy.AllowParallel, CancellationToken);

        await Task.Delay(50, CancellationToken);
        Assert.False(second.IsCompleted);

        first.Dispose();
        using IDisposable secondSlot = await second.WaitAsync(TimeSpan.FromSeconds(2), CancellationToken);
    }

    [Fact]
    public async Task NoOverlapDoesNotBlockDifferentJobs()
    {
        using ConcurrencyGate gate = new(new ExecutionOptions { GlobalConcurrencyLimit = 8 });

        using IDisposable first = await gate.AcquireAsync("job-1", ConcurrencyPolicy.DisallowOverlap, CancellationToken);
        Task<IDisposable> second = gate.AcquireAsync("job-2", ConcurrencyPolicy.DisallowOverlap, CancellationToken);

        using IDisposable secondSlot = await second.WaitAsync(TimeSpan.FromSeconds(2), CancellationToken);
    }
}

using System.Collections.Concurrent;
using Scheduler.Contracts.Execution;

namespace Scheduler.Application.Execution;

/// <summary>
/// Admits executions under a global concurrency limit and a per-job policy.
/// <see cref="ConcurrencyPolicy.DisallowOverlap" /> (the default) admits at most
/// one execution per job at a time; <see cref="ConcurrencyPolicy.AllowParallel" />
/// is bounded only by the global limit.
/// </summary>
public sealed class ConcurrencyGate : IDisposable
{
    private readonly SemaphoreSlim _global;
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _perJob = new(StringComparer.Ordinal);

    public ConcurrencyGate(ExecutionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(options.GlobalConcurrencyLimit);

        _global = new SemaphoreSlim(options.GlobalConcurrencyLimit, options.GlobalConcurrencyLimit);
    }

    /// <summary>
    /// Waits for a slot, honoring the job's concurrency policy. The per-job slot
    /// is taken before the global slot so a queued no-overlap job never holds a
    /// global slot while it waits.
    /// </summary>
    public async Task<IDisposable> AcquireAsync(
        string jobId,
        ConcurrencyPolicy policy,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(jobId);

        SemaphoreSlim? perJob = policy == ConcurrencyPolicy.DisallowOverlap
            ? _perJob.GetOrAdd(jobId, static _ => new SemaphoreSlim(1, 1))
            : null;

        if (perJob is not null)
        {
            await perJob.WaitAsync(cancellationToken);
        }

        try
        {
            await _global.WaitAsync(cancellationToken);
        }
        catch
        {
            perJob?.Release();
            throw;
        }

        return new Slot(perJob, _global);
    }

    public void Dispose()
    {
        _global.Dispose();
        foreach (SemaphoreSlim perJob in _perJob.Values)
        {
            perJob.Dispose();
        }
    }

    private sealed class Slot(SemaphoreSlim? perJob, SemaphoreSlim global) : IDisposable
    {
        private bool _released;

        public void Dispose()
        {
            if (_released)
            {
                return;
            }

            _released = true;
            global.Release();
            perJob?.Release();
        }
    }
}

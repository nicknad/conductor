using Scheduler.Contracts.Execution;

namespace Scheduler.Application.Execution;

/// <summary>How a failure should be treated by the retry engine.</summary>
public enum FailureKind
{
    /// <summary>Transient or unknown; a bounded retry is allowed.</summary>
    Retryable,

    /// <summary>Known-permanent; retrying cannot succeed and is not attempted.</summary>
    NonRetryable,
}

/// <summary>The retry engine's decision after a failed attempt.</summary>
public sealed record RetryDecision(bool ShouldRetry, TimeSpan Delay, int NextAttempt)
{
    public static RetryDecision Stop(int failedAttempt) => new(ShouldRetry: false, TimeSpan.Zero, failedAttempt);
}

/// <summary>
/// Evaluates a bounded retry policy with exponential backoff and jitter.
/// Jitter is always additive-up (never below the base delay) and never pushes a
/// delay past <see cref="RetryPolicy.MaxDelay" />.
/// </summary>
public sealed class RetryPolicyEvaluator(double jitterRatio = 0.2)
{
    private const double MaxAllowedJitterRatio = 0.5;

    public double JitterRatio { get; } =
        jitterRatio is < 0.0 or > MaxAllowedJitterRatio
            ? throw new ArgumentOutOfRangeException(nameof(jitterRatio), "Jitter ratio must be within [0.0, 0.5].")
            : jitterRatio;

    public RetryDecision Evaluate(RetryPolicy policy, int failedAttempt, FailureKind failureKind)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentOutOfRangeException.ThrowIfLessThan(failedAttempt, 1);

        if (failureKind == FailureKind.NonRetryable || failedAttempt >= policy.MaxAttempts)
        {
            return RetryDecision.Stop(failedAttempt);
        }

        double baseMilliseconds = policy.InitialDelay.TotalMilliseconds *
            Math.Pow(policy.BackoffMultiplier, failedAttempt - 1);
        double jitterFactor = 1.0 + (Random.Shared.NextDouble() * JitterRatio);
        double delayMilliseconds = Math.Min(
            baseMilliseconds * jitterFactor,
            policy.MaxDelay.TotalMilliseconds);

        return new RetryDecision(
            ShouldRetry: true,
            TimeSpan.FromMilliseconds(delayMilliseconds),
            failedAttempt + 1);
    }
}

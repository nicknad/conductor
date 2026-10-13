using Scheduler.Application.Execution;
using Scheduler.Contracts.Execution;

namespace Scheduler.Tests.Unit;

public sealed class RetryPolicyEvaluatorTests
{
    private static readonly RetryPolicy Policy = new()
    {
        MaxAttempts = 3,
        InitialDelay = TimeSpan.FromSeconds(1),
        BackoffMultiplier = 2.0,
        MaxDelay = TimeSpan.FromSeconds(60),
    };

    private readonly RetryPolicyEvaluator _evaluator = new();

    [Fact]
    public void NonRetryableFailuresAreNeverRetried()
    {
        RetryDecision decision = _evaluator.Evaluate(Policy, failedAttempt: 1, FailureKind.NonRetryable);

        Assert.False(decision.ShouldRetry);
        Assert.Equal(TimeSpan.Zero, decision.Delay);
        Assert.Equal(1, decision.NextAttempt);
    }

    [Fact]
    public void ExhaustedAttemptsAreNotRetried()
    {
        RetryDecision decision = _evaluator.Evaluate(Policy, failedAttempt: 3, FailureKind.Retryable);

        Assert.False(decision.ShouldRetry);
        Assert.Equal(3, decision.NextAttempt);
    }

    [Fact]
    public void AttemptsBelowOneAreRejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => _evaluator.Evaluate(Policy, failedAttempt: 0, FailureKind.Retryable));
    }

    [Fact]
    public void FirstRetryDelayStaysWithinJitterBounds()
    {
        for (int i = 0; i < 100; i++)
        {
            RetryDecision decision = _evaluator.Evaluate(Policy, failedAttempt: 1, FailureKind.Retryable);

            Assert.True(decision.Delay >= TimeSpan.FromSeconds(1), $"Too small: {decision.Delay}");
            Assert.True(decision.Delay <= TimeSpan.FromSeconds(1.2), $"Too large: {decision.Delay}");
        }
    }

    [Fact]
    public void DelaysGrowExponentiallyWithBackoff()
    {
        RetryPolicy longerPolicy = Policy with { MaxAttempts = 5 };

        for (int i = 0; i < 100; i++)
        {
            RetryDecision second = _evaluator.Evaluate(longerPolicy, failedAttempt: 2, FailureKind.Retryable);
            RetryDecision third = _evaluator.Evaluate(longerPolicy, failedAttempt: 3, FailureKind.Retryable);

            Assert.InRange(second.Delay, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(2.4));
            Assert.InRange(third.Delay, TimeSpan.FromSeconds(4), TimeSpan.FromSeconds(4.8));
        }
    }

    [Fact]
    public void DelaysNeverExceedMaxDelay()
    {
        RetryPolicy cappedPolicy = Policy with { MaxAttempts = 10, MaxDelay = TimeSpan.FromSeconds(2.5) };

        for (int i = 0; i < 100; i++)
        {
            RetryDecision decision = _evaluator.Evaluate(cappedPolicy, failedAttempt: 9, FailureKind.Retryable);

            Assert.True(decision.ShouldRetry);
            Assert.True(decision.Delay <= TimeSpan.FromSeconds(2.5), $"Exceeded cap: {decision.Delay}");
        }
    }

    [Fact]
    public void JitterRatioMustBeWithinBounds()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new RetryPolicyEvaluator(jitterRatio: 0.6));
        Assert.Throws<ArgumentOutOfRangeException>(() => new RetryPolicyEvaluator(jitterRatio: -0.1));
    }
}

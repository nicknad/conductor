namespace Scheduler.Contracts.Execution;

/// <summary>Outcome of one execution attempt.</summary>
public sealed record JobResult
{
    public required JobOutcome Outcome { get; init; }

    /// <summary>Short, sanitized summary of the result. Must never contain secret values.</summary>
    public string? Summary { get; init; }

    /// <summary>Optional structured result data (serializable values only).</summary>
    public IReadOnlyDictionary<string, string?> Data { get; init; } =
        new Dictionary<string, string?>();

    /// <summary>
    /// Whether the failure is considered transient and eligible for a bounded
    /// retry. Only meaningful when <see cref="Outcome" /> is
    /// <see cref="JobOutcome.Failed" />. A thrown execution exception is always
    /// treated as retryable; a reported failure defaults to non-retryable.
    /// </summary>
    public bool Retryable { get; init; }

    public static JobResult Succeeded(string? summary = null) => new() { Outcome = JobOutcome.Succeeded, Summary = summary };

    public static JobResult Failed(string summary) => Failed(summary, retryable: false);

    public static JobResult Failed(string summary, bool retryable) =>
        new() { Outcome = JobOutcome.Failed, Summary = summary, Retryable = retryable };
}

public enum JobOutcome
{
    Succeeded,
    Failed,
}

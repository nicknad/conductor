using Scheduler.Application.Observability;
using Scheduler.Application.Secrets;
using Scheduler.Contracts.Execution;
using Scheduler.Contracts.Secrets;

namespace Scheduler.Runtime.InProcess.Execution;

/// <summary>Discards plugin log output. Used by tests and backends without a log store.</summary>
public sealed class NullJobExecutionLogger : IJobExecutionLogger
{
    public void Log(JobLogLevel level, string message, Exception? exception = null)
    {
    }
}

/// <summary>Discards progress reports. Used by tests and backends without a log store.</summary>
public sealed class NullJobProgressReporter : IJobProgressReporter
{
    public void Report(int percent, string? stage = null)
    {
    }
}

/// <summary>Creates no-op execution scopes; used by tests and backends without log capture.</summary>
public sealed class NullExecutionLoggerFactory : IExecutionLoggerFactory
{
    private static readonly NullJobExecutionLogger Logger = new();
    private static readonly NullJobProgressReporter Progress = new();

    public IJobExecutionLogger CreateLogger(ExecutionIdentity identity) => Logger;

    public IJobProgressReporter CreateProgressReporter(ExecutionIdentity identity) => Progress;
}

/// <summary>
/// Denies every secret resolution. Used by tests and backends without a secret
/// store; jobs that declare no secret references never touch it.
/// </summary>
public sealed class DeniedSecretProvider : ISecretProvider
{
    public Task<string> ResolveAsync(string secretReference, CancellationToken cancellationToken = default)
    {
        throw new SecretNotAuthorizedException(secretReference);
    }
}

/// <summary>Provides a shared denying provider; used by tests and backends without secrets.</summary>
public sealed class DeniedSecretProviderFactory : ISecretProviderFactory
{
    private static readonly DeniedSecretProvider Provider = new();

    public Task<ISecretProvider> CreateAsync(ExecutionIdentity identity, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(identity);
        return Task.FromResult<ISecretProvider>(Provider);
    }
}

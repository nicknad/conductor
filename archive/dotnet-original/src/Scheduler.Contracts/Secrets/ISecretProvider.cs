namespace Scheduler.Contracts.Secrets;

/// <summary>
/// Resolves authorized secret references to values. The instance handed to a
/// job execution is restricted to the references granted to that job by
/// platform policy; ungranted references must be denied.
/// </summary>
/// <remarks>
/// This is an authorization boundary, not a sandbox: an in-process plugin can
/// potentially access host memory. Values must never be logged.
/// </remarks>
public interface ISecretProvider
{
    /// <summary>Resolves a secret reference the caller is authorized for.</summary>
    /// <exception cref="SecretNotAuthorizedException">The reference is not granted to the caller.</exception>
    Task<string> ResolveAsync(string secretReference, CancellationToken cancellationToken = default);
}

/// <summary>Thrown when a secret reference has not been granted to the requesting execution.</summary>
public sealed class SecretNotAuthorizedException(string secretReference)
    : Exception($"Access to secret reference '{secretReference}' was not granted to this execution.")
{
    public string SecretReference { get; } = secretReference;
}

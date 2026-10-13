namespace Scheduler.Application.Packaging;

/// <summary>
/// Raised when a package violates a validation gate (archive safety, manifest,
/// digest, signature, or assembly-level checks). The associated version is
/// rejected; the active version is never affected. Distinct from I/O or
/// infrastructure failures, which propagate and fail the operation.
/// </summary>
public sealed class PackageValidationException : Exception
{
    public PackageValidationException(IReadOnlyList<string> errors)
        : base(string.Join("; ", errors))
    {
        Errors = errors;
    }

    public PackageValidationException()
        : this([])
    {
    }

    public PackageValidationException(string message)
        : base(message)
    {
        Errors = [message];
    }

    public PackageValidationException(string message, Exception innerException)
        : base(message, innerException)
    {
        Errors = [message];
    }

    public IReadOnlyList<string> Errors { get; }
}

using Scheduler.Contracts.Jobs;

namespace Scheduler.Application.Persistence;

/// <summary>
/// A persisted job definition together with the registry-owned revision used to
/// derive triggers. The definition stays data-only, per the job contract.
/// </summary>
public sealed record JobRecord
{
    public required JobDefinition Definition { get; init; }

    /// <summary>Monotonic configuration revision; bumped on every update.</summary>
    public required int ConfigurationRevision { get; init; }

    public required DateTimeOffset UpdatedAt { get; init; }
}

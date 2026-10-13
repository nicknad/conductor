namespace Scheduler.Application.Maintenance;

/// <summary>Outcome of a consistent backup: where it landed and whether it verified.</summary>
public sealed record BackupResult(string Root, int ArtifactCount, bool Verified);

/// <summary>Verification of a backup: whether every recorded artifact hash still matches.</summary>
public sealed record BackupVerification(bool Verified, int VerifiedArtifacts, IReadOnlyList<string> Failures);

/// <summary>
/// Consistent backup of the authoritative state: a SQLite checkpoint of the
/// registry plus a snapshot of the artifact store, recorded with artifact
/// hashes so a restore can be verified.
/// </summary>
public interface IBackupService
{
    Task<BackupResult> CreateAsync(string destinationRoot, CancellationToken cancellationToken = default);

    Task<BackupVerification> VerifyAsync(string backupRoot, CancellationToken cancellationToken = default);
}

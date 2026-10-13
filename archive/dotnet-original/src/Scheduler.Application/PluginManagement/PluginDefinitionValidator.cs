using Scheduler.Contracts.Jobs;

namespace Scheduler.Application.PluginManagement;

/// <summary>
/// Validates the job definitions a plugin proposes during activation:
/// per-definition shape, plugin identity consistency, and uniqueness of job ids.
/// Definitions returned by <c>GetJobs()</c> are proposals; the registry remains
/// authoritative for what is scheduled.
/// </summary>
public static class PluginDefinitionValidator
{
    public static IReadOnlyList<string> Validate(
        string pluginId,
        Version version,
        IReadOnlyCollection<JobDefinition> jobs)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pluginId);
        ArgumentNullException.ThrowIfNull(version);
        ArgumentNullException.ThrowIfNull(jobs);

        List<string> errors = [];
        HashSet<string> jobIds = new(StringComparer.Ordinal);

        foreach (JobDefinition job in jobs)
        {
            foreach (string error in job.Validate())
            {
                errors.Add($"{job.JobId}: {error}");
            }

            if (!string.Equals(job.PluginId, pluginId, StringComparison.Ordinal))
            {
                errors.Add(
                    $"{job.JobId}: definition plugin id '{job.PluginId}' does not match '{pluginId}'.");
            }

            if (job.PluginVersion != version)
            {
                errors.Add(
                    $"{job.JobId}: definition plugin version '{job.PluginVersion}' does not match '{version}'.");
            }

            if (!jobIds.Add(job.JobId))
            {
                errors.Add($"Duplicate job id '{job.JobId}'.");
            }
        }

        return errors;
    }
}

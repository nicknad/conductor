namespace Scheduler.Application.Packaging;

/// <summary>
/// Decides whether a plugin manifest's declared <c>contractVersion</c> can run
/// against the host contract. Compatible means the same major version and not
/// newer than the host; there is no silent major-version acceptance.
/// </summary>
public static class ContractCompatibility
{
    public static bool IsCompatible(Version hostVersion, Version pluginVersion)
    {
        ArgumentNullException.ThrowIfNull(hostVersion);
        ArgumentNullException.ThrowIfNull(pluginVersion);

        return Normalize(pluginVersion).Major == Normalize(hostVersion).Major
            && Normalize(pluginVersion) <= Normalize(hostVersion);
    }

    public static string Describe(Version hostVersion, Version pluginVersion)
    {
        ArgumentNullException.ThrowIfNull(hostVersion);
        ArgumentNullException.ThrowIfNull(pluginVersion);

        if (IsCompatible(hostVersion, pluginVersion))
        {
            return $"Contract version '{pluginVersion}' is compatible with host '{hostVersion}'.";
        }

        return pluginVersion.Major != hostVersion.Major
            ? $"Contract major version '{pluginVersion.Major}' is not accepted by host contract '{hostVersion.Major}'."
            : $"Contract version '{pluginVersion}' is newer than the host contract '{hostVersion}'.";
    }

    private static Version Normalize(Version version) =>
        new(version.Major, Math.Max(version.Minor, 0), Math.Max(version.Build, 0));
}

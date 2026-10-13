namespace Scheduler.Contracts;

/// <summary>
/// The version of the host contract exposed by <c>Scheduler.Contracts</c>. Plugin
/// manifests declare the contract version they were built against; the host
/// accepts a plugin whose declared version shares this major and is not newer.
/// </summary>
/// <remarks>
/// This value must track the assembly version of <c>Scheduler.Contracts</c>. A
/// test asserts the two cannot drift.
/// </remarks>
public static class SchedulerContract
{
    public const int MajorVersion = 1;

    public const int MinorVersion = 0;

    public static Version CurrentVersion { get; } = new(MajorVersion, MinorVersion);
}

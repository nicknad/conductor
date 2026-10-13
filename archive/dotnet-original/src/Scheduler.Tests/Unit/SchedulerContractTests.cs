using Scheduler.Contracts;
using Scheduler.Contracts.Plugins;

namespace Scheduler.Tests.Unit;

public sealed class SchedulerContractTests
{
    [Fact]
    public void CurrentVersionTracksContractAssemblyVersion()
    {
        Version assemblyVersion = typeof(IJobPlugin).Assembly.GetName().Version!;

        Assert.Equal(SchedulerContract.MajorVersion, assemblyVersion.Major);
        Assert.Equal(SchedulerContract.MinorVersion, assemblyVersion.Minor);
    }

    [Fact]
    public void CurrentVersionIsOneZero()
    {
        Assert.Equal(new Version(1, 0), SchedulerContract.CurrentVersion);
    }
}

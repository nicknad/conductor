using Scheduler.Application.Packaging;

namespace Scheduler.Tests.Unit.Packaging;

public sealed class ContractCompatibilityTests
{
    private static readonly Version Host = new(1, 2);

    [Theory]
    [InlineData("1.0")]
    [InlineData("1.1")]
    [InlineData("1.2")]
    public void AcceptsSameMajorAtOrBelowHost(string plugin)
    {
        Assert.True(ContractCompatibility.IsCompatible(Host, Version.Parse(plugin)));
    }

    [Theory]
    [InlineData("1.3")]
    [InlineData("2.0")]
    [InlineData("0.9")]
    public void RejectsNewerMinorOrDifferentMajor(string plugin)
    {
        Assert.False(ContractCompatibility.IsCompatible(Host, Version.Parse(plugin)));
    }

    [Fact]
    public void DescribeExplainsMajorMismatch()
    {
        string description = ContractCompatibility.Describe(new Version(2, 0), new Version(1, 0));

        Assert.Contains("major", description, StringComparison.OrdinalIgnoreCase);
    }
}

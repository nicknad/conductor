using Scheduler.Example.Plugin;

namespace Scheduler.Tests.Unit.Example;

public sealed class ReportDigestTests
{
    [Fact]
    public void IsDeterministicAndShort()
    {
        string first = ReportDigest.OfValue("example-value");
        string second = ReportDigest.OfValue("example-value");

        Assert.Equal(first, second);
        Assert.Equal(12, first.Length);
        Assert.All(first, character => Assert.True(char.IsAsciiHexDigitLower(character), $"Unexpected character '{character}'."));
    }

    [Fact]
    public void DiffersForDifferentValues()
    {
        Assert.NotEqual(ReportDigest.OfValue("value-one"), ReportDigest.OfValue("value-two"));
    }

    [Fact]
    public void NeverContainsTheValue()
    {
        const string value = "super-secret-key";
        Assert.DoesNotContain(value, ReportDigest.OfValue(value), StringComparison.OrdinalIgnoreCase);
    }
}

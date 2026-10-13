using System.Text;
using Scheduler.Application.Packaging;

namespace Scheduler.Tests.Unit.Packaging;

public sealed class PackageSignatureJsonTests
{
    [Fact]
    public void ParsesValidSignature()
    {
        byte[] signature = [1, 2, 3, 4];
        string json = $$"""{"formatVersion":1,"algorithm":"ES256","signature":"{{Convert.ToBase64String(signature)}}"}""";

        PackageSignatureParseResult result = PackageSignatureJson.Parse(Encoding.UTF8.GetBytes(json));

        Assert.True(result.IsValid);
        Assert.Equal(PackageSignatureAlgorithm.Es256, result.Signature!.Algorithm);
        Assert.Equal(signature, result.Signature.Signature);
    }

    [Fact]
    public void RejectsUnsupportedAlgorithm()
    {
        PackageSignatureParseResult result = PackageSignatureJson.Parse(
            Encoding.UTF8.GetBytes("""{"formatVersion":1,"algorithm":"HS256","signature":"AQ=="}"""));

        Assert.False(result.IsValid);
    }

    [Fact]
    public void RejectsUnsupportedFormatVersion()
    {
        PackageSignatureParseResult result = PackageSignatureJson.Parse(
            Encoding.UTF8.GetBytes("""{"formatVersion":2,"algorithm":"RS256","signature":"AQ=="}"""));

        Assert.False(result.IsValid);
    }

    [Fact]
    public void RejectsInvalidBase64()
    {
        PackageSignatureParseResult result = PackageSignatureJson.Parse(
            Encoding.UTF8.GetBytes("""{"formatVersion":1,"algorithm":"RS256","signature":"not base64!"}"""));

        Assert.False(result.IsValid);
    }
}

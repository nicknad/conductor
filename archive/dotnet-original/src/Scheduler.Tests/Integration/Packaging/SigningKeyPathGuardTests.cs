using System.IO.Abstractions;
using Scheduler.Infrastructure.Packaging;

namespace Scheduler.Tests.Integration.Packaging;

public sealed class SigningKeyPathGuardTests : IDisposable
{
    private readonly string _directory;
    private readonly IFileSystem _fileSystem = new FileSystem();

    public SigningKeyPathGuardTests()
    {
        _directory = Path.Combine(Path.GetTempPath(), "jobscheduler-keyguard", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_directory);
    }

    [Fact]
    public void AcceptsKeyOutsideWritableRoots()
    {
        string keyPath = Path.Combine(_directory, "keys", "public.pem");
        Directory.CreateDirectory(Path.GetDirectoryName(keyPath)!);
        File.WriteAllText(keyPath, "key");

        SigningKeyPathGuard.EnsureOutsideWritableRoots(NewOptions(keyPath), _fileSystem);
    }

    [Fact]
    public void RejectsKeyInsideWritableRoot()
    {
        string artifacts = Path.Combine(_directory, "artifacts");
        Directory.CreateDirectory(artifacts);
        string keyPath = Path.Combine(artifacts, "public.pem");
        File.WriteAllText(keyPath, "key");

        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(
            () => SigningKeyPathGuard.EnsureOutsideWritableRoots(NewOptions(keyPath), _fileSystem));

        Assert.Contains("outside", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void RejectsMissingKey()
    {
        string keyPath = Path.Combine(_directory, "keys", "missing.pem");

        Assert.Throws<InvalidOperationException>(
            () => SigningKeyPathGuard.EnsureOutsideWritableRoots(NewOptions(keyPath), _fileSystem));
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (DirectoryNotFoundException)
        {
        }
        catch (IOException)
        {
        }
    }

    private PackagingOptions NewOptions(string keyPath) => new()
    {
        ArtifactsRoot = Path.Combine(_directory, "artifacts"),
        StagingRoot = Path.Combine(_directory, "staging"),
        PublicKeyPath = keyPath,
        DataRoot = Path.Combine(_directory, "data"),
        LogsRoot = Path.Combine(_directory, "logs"),
        BaseDirectory = _directory,
    };
}

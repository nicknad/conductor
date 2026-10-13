using System.IO.Abstractions;
using Scheduler.Infrastructure.Persistence;

namespace Scheduler.Tests.Integration;

public sealed class ConnectionFactoryTests
{
    [Fact]
    public void FactoryCreatesParentDirectory()
    {
        string root = Path.Combine(Path.GetTempPath(), "jobscheduler-tests", Guid.NewGuid().ToString("N"));
        string directory = Path.Combine(root, "nested");
        try
        {
            PersistenceOptions options = new() { DatabasePath = Path.Combine(directory, "registry.db") };

            _ = new SqliteConnectionFactory(options, new FileSystem());

            Assert.True(Directory.Exists(directory));
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [Fact]
    public void FactorySurfacesDirectoryProvisioningFailure()
    {
        PersistenceOptions options = new()
        {
            DatabasePath = "data/registry.db",
            BaseDirectory = Path.GetTempPath(),
        };

        Assert.Throws<IOException>(() => new SqliteConnectionFactory(options, new ThrowingFileSystem()));
    }

    [Fact]
    public void RelativePathWithoutBaseDirectoryIsRejected()
    {
        PersistenceOptions options = new() { DatabasePath = "data/registry.db" };

        Assert.Throws<InvalidOperationException>(() => new SqliteConnectionFactory(options, new FileSystem()));
    }

    private sealed class ThrowingFileSystem : FileSystem
    {
        public override IDirectory Directory => throw new IOException("Data root is unavailable.");
    }
}

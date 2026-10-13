using System.Text;
using Scheduler.Application.Packaging;
using Scheduler.Application.Persistence;
using Scheduler.Application.PluginManagement;
using Scheduler.Contracts.Execution;
using Scheduler.Tests.Support;

namespace Scheduler.Tests.Integration.Packaging;

/// <summary>Acceptance criterion #2: bad packages are rejected and the active version is untouched.</summary>
public sealed class PackageValidationFailureTests
{
    private static readonly Version ActiveVersion = new(1, 0, 0);

    private const string ActiveArtifactPath = "artifacts/monthly-report/1.0.0";

    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task TamperedPayloadIsRejected()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using PackagingTestContext context = new(key.PublicKeyPath);
        await context.InitializeAsync(CancellationToken);
        await SeedActiveVersionAsync(context);

        IReadOnlyList<(string, byte[])> tamperedPayload =
        [
            ("MonthlyReport.dll", Encoding.UTF8.GetBytes("tampered")),
            ("MonthlyReport.deps.json", Encoding.UTF8.GetBytes("{}")),
        ];
        byte[] package = TestPackage.Create(
            TestPackage.NewManifest(version: "2.0.0"),
            TestPackage.DefaultPayload(),
            tamperedPayload,
            key);

        await AssertRejectedAsync(context, package, new Version(2, 0, 0));
    }

    [Fact]
    public async Task PackageSignedByAnotherKeyIsRejected()
    {
        using TestPackageKey trusted = TestPackageKey.CreateRsa();
        using TestPackageKey attacker = TestPackageKey.CreateRsa();
        using PackagingTestContext context = new(trusted.PublicKeyPath);
        await context.InitializeAsync(CancellationToken);
        await SeedActiveVersionAsync(context);

        byte[] package = TestPackage.CreateSigned(
            TestPackage.NewManifest(version: "2.0.0"),
            TestPackage.DefaultPayload(),
            attacker);

        await AssertRejectedAsync(context, package, new Version(2, 0, 0));
    }

    [Fact]
    public async Task IncompatibleContractVersionIsRejected()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using PackagingTestContext context = new(key.PublicKeyPath);
        await context.InitializeAsync(CancellationToken);
        await SeedActiveVersionAsync(context);

        byte[] package = TestPackage.CreateSigned(
            TestPackage.NewManifest(version: "2.0.0", contractVersion: "2.0"),
            TestPackage.DefaultPayload(),
            key);

        await AssertRejectedAsync(context, package, new Version(2, 0, 0));
    }

    [Fact]
    public async Task PublishedVersionCannotBeOverwrittenWithDifferentContent()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using PackagingTestContext context = new(key.PublicKeyPath);
        await context.InitializeAsync(CancellationToken);

        PluginManifest manifest = TestPackage.NewManifest(version: "2.0.0");
        byte[] original = TestPackage.CreateSigned(manifest, TestPackage.DefaultPayload(), key);
        Assert.Equal(PluginOperationStatus.Succeeded, (await context.Manager.InstallAsync(new MemoryStream(original), CancellationToken)).Status);

        IReadOnlyList<(string, byte[])> replacementPayload =
        [
            ("MonthlyReport.dll", Encoding.UTF8.GetBytes("a-different-assembly")),
            ("MonthlyReport.deps.json", Encoding.UTF8.GetBytes("{}")),
        ];
        byte[] replacement = TestPackage.CreateSigned(manifest, replacementPayload, key);

        PluginOperation operation = await context.Manager.InstallAsync(new MemoryStream(replacement), CancellationToken);

        Assert.Equal(PluginOperationStatus.Failed, operation.Status);

        await using IRegistryUnitOfWork unitOfWork = await context.UnitOfWorkFactory.BeginAsync(CancellationToken);
        PluginVersionRecord? record = await unitOfWork.Plugins.GetVersionAsync("monthly-report", new Version(2, 0, 0), CancellationToken);
        Assert.NotNull(record);
        Assert.Equal(PluginLifecycleState.Staged, record.State);
    }

    [Fact]
    public async Task MissingManifestIsRejected()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using PackagingTestContext context = new(key.PublicKeyPath);
        await context.InitializeAsync(CancellationToken);
        await SeedActiveVersionAsync(context);

        byte[] package = TestPackage.Zip(
        [
            ("MonthlyReport.dll", Encoding.UTF8.GetBytes("assembly")),
            ("signature.json", Encoding.UTF8.GetBytes("{}")),
        ]);

        PluginOperation operation = await context.Manager.InstallAsync(new MemoryStream(package), CancellationToken);

        Assert.Equal(PluginOperationStatus.Failed, operation.Status);
        await AssertActivationUnchangedAsync(context);
    }

    [Fact]
    public async Task MissingSignatureIsRejected()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using PackagingTestContext context = new(key.PublicKeyPath);
        await context.InitializeAsync(CancellationToken);
        await SeedActiveVersionAsync(context);

        byte[] package = TestPackage.CreateUnsigned(TestPackage.NewManifest(version: "2.0.0"), TestPackage.DefaultPayload());

        await AssertRejectedAsync(context, package, new Version(2, 0, 0));
    }

    [Fact]
    public async Task BadPackageDeclaringPublishedVersionDoesNotMutateIt()
    {
        using TestPackageKey trusted = TestPackageKey.CreateRsa();
        using TestPackageKey attacker = TestPackageKey.CreateRsa();
        using PackagingTestContext context = new(trusted.PublicKeyPath);
        await context.InitializeAsync(CancellationToken);
        await SeedActiveVersionAsync(context);

        // A tampered package that declares the currently Active version must be
        // rejected without downgrading the live registry record.
        byte[] package = TestPackage.CreateSigned(
            TestPackage.NewManifest(version: "1.0.0"),
            TestPackage.DefaultPayload(),
            attacker);

        PluginOperation operation = await context.Manager.InstallAsync(new MemoryStream(package), CancellationToken);
        Assert.Equal(PluginOperationStatus.Failed, operation.Status);

        await using (IRegistryUnitOfWork unitOfWork = await context.UnitOfWorkFactory.BeginAsync(CancellationToken))
        {
            PluginVersionRecord? active = await unitOfWork.Plugins.GetVersionAsync("monthly-report", ActiveVersion, CancellationToken);
            Assert.NotNull(active);
            Assert.Equal(PluginLifecycleState.Active, active.State);
            Assert.Equal(ActiveArtifactPath, active.ArtifactPath);
        }

        await AssertActivationUnchangedAsync(context);
    }

    [Fact]
    public async Task PathTraversalEntryIsRejected()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using PackagingTestContext context = new(key.PublicKeyPath);
        await context.InitializeAsync(CancellationToken);
        await SeedActiveVersionAsync(context);

        // Otherwise-valid, correctly-signed package whose only fault is the traversal.
        IReadOnlyList<(string, byte[])> payload =
        [
            ("MonthlyReport.dll", Encoding.UTF8.GetBytes("assembly")),
            ("../evil.dll", Encoding.UTF8.GetBytes("evil")),
        ];
        byte[] package = TestPackage.CreateSigned(TestPackage.NewManifest(version: "2.0.0"), payload, key);

        PluginOperation operation = await context.Manager.InstallAsync(new MemoryStream(package), CancellationToken);

        Assert.Equal(PluginOperationStatus.Failed, operation.Status);
        Assert.Contains("unsafe path", operation.Error!, StringComparison.OrdinalIgnoreCase);
        await AssertActivationUnchangedAsync(context);
    }

    [Fact]
    public async Task DuplicateEntriesAreRejected()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        using PackagingTestContext context = new(key.PublicKeyPath);
        await context.InitializeAsync(CancellationToken);
        await SeedActiveVersionAsync(context);

        IReadOnlyList<(string, byte[])> payload =
        [
            ("MonthlyReport.dll", Encoding.UTF8.GetBytes("assembly")),
            ("MonthlyReport.dll", Encoding.UTF8.GetBytes("other")),
        ];
        byte[] package = TestPackage.CreateSigned(TestPackage.NewManifest(version: "2.0.0"), payload, key);

        PluginOperation operation = await context.Manager.InstallAsync(new MemoryStream(package), CancellationToken);

        Assert.Equal(PluginOperationStatus.Failed, operation.Status);
        Assert.Contains("duplicate", operation.Error!, StringComparison.OrdinalIgnoreCase);
        await AssertActivationUnchangedAsync(context);
    }

    [Fact]
    public async Task OversizedEntryIsRejected()
    {
        using TestPackageKey key = TestPackageKey.CreateRsa();
        PackagingLimits limits = new(
            MaxEntryCount: 10,
            MaxEntryUncompressedBytes: 8,
            MaxTotalUncompressedBytes: 64,
            MaxCompressionRatio: 1000);
        using PackagingTestContext context = new(key.PublicKeyPath, limits);
        await context.InitializeAsync(CancellationToken);

        byte[] package = TestPackage.CreateSigned(
            TestPackage.NewManifest(),
            [("MonthlyReport.dll", Encoding.UTF8.GetBytes("this-is-much-longer-than-eight-bytes"))],
            key);

        PluginOperation operation = await context.Manager.InstallAsync(new MemoryStream(package), CancellationToken);

        Assert.Equal(PluginOperationStatus.Failed, operation.Status);
    }

    private static async Task AssertRejectedAsync(PackagingTestContext context, byte[] package, Version version)
    {
        PluginOperation operation = await context.Manager.InstallAsync(new MemoryStream(package), CancellationToken);

        Assert.Equal(PluginOperationStatus.Failed, operation.Status);

        await using (IRegistryUnitOfWork unitOfWork = await context.UnitOfWorkFactory.BeginAsync(CancellationToken))
        {
            PluginVersionRecord? record = await unitOfWork.Plugins.GetVersionAsync("monthly-report", version, CancellationToken);
            if (record is not null)
            {
                Assert.Equal(PluginLifecycleState.Rejected, record.State);
            }
        }

        await AssertActivationUnchangedAsync(context);
    }

    private static async Task AssertActivationUnchangedAsync(PackagingTestContext context)
    {
        await using IRegistryUnitOfWork unitOfWork = await context.UnitOfWorkFactory.BeginAsync(CancellationToken);
        PluginActivationRecord? activation = await unitOfWork.Plugins.GetActivationAsync("monthly-report", CancellationToken);
        PluginVersionRecord? active = await unitOfWork.Plugins.GetVersionAsync("monthly-report", ActiveVersion, CancellationToken);

        Assert.NotNull(activation);
        Assert.Equal(ActiveVersion, activation.Version);
        Assert.NotNull(active);
        Assert.Equal(PluginLifecycleState.Active, active.State);
    }

    private static async Task SeedActiveVersionAsync(PackagingTestContext context)
    {
        DateTimeOffset now = context.TimeProvider.GetUtcNow();
        await using IRegistryUnitOfWork unitOfWork = await context.UnitOfWorkFactory.BeginAsync(CancellationToken);
        await unitOfWork.Plugins.UpsertVersionAsync(
            new PluginVersionRecord
            {
                PluginId = "monthly-report",
                Version = ActiveVersion,
                ContractVersion = "1.0",
                EntryAssembly = "MonthlyReport.dll",
                EntryType = "MonthlyReport.Plugin",
                ExecutionMode = ExecutionMode.InProcess,
                ArtifactHash = CanonicalPackageDigest.Format(CanonicalPackageDigest.ComputeHash([])),
                State = PluginLifecycleState.Active,
                InstalledAt = now,
                ValidatedAt = now,
                ArtifactPath = ActiveArtifactPath,
            },
            CancellationToken);
        await unitOfWork.Plugins.SetActivationAsync(
            new PluginActivationRecord
            {
                PluginId = "monthly-report",
                Version = ActiveVersion,
                ActivatedAt = now,
                ActivatedBy = "test",
            },
            CancellationToken);
        await unitOfWork.CommitAsync(CancellationToken);
    }
}

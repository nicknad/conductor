using System.Text;
using Scheduler.Application.Execution;
using Scheduler.Application.Packaging;
using Scheduler.Application.Persistence;
using Scheduler.Application.Reconciliation;
using Scheduler.Contracts.Jobs;

namespace Scheduler.Application.PluginManagement;

/// <summary>
/// Authoritative lifecycle use cases. Install stages and validates packages;
/// activation loads a version, validates its definitions, and publishes the
/// active version atomically; deactivation, rollback, and removal drive draining
/// and cooperative unload.
/// </summary>
public sealed class PluginManager : IPluginManager
{
    private const string Actor = "local";

    private readonly IRegistryUnitOfWorkFactory _unitOfWorkFactory;
    private readonly IPackageArchiveReader _archiveReader;
    private readonly IArtifactStore _artifactStore;
    private readonly PackageValidator _validator;
    private readonly IAuditWriter _auditWriter;
    private readonly TimeProvider _timeProvider;
    private readonly PackagingLimits _limits;
    private readonly Version _hostContractVersion;
    private readonly IPluginRuntime _pluginRuntime;
    private readonly IRunningExecutionRegistry _runningExecutions;
    private readonly ExecutionOptions _executionOptions;

    public PluginManager(
        IRegistryUnitOfWorkFactory unitOfWorkFactory,
        IPackageArchiveReader archiveReader,
        IArtifactStore artifactStore,
        PackageValidator validator,
        IAuditWriter auditWriter,
        TimeProvider timeProvider,
        PackagingLimits limits,
        Version hostContractVersion,
        IPluginRuntime pluginRuntime,
        IRunningExecutionRegistry runningExecutions,
        ExecutionOptions executionOptions)
    {
        ArgumentNullException.ThrowIfNull(unitOfWorkFactory);
        ArgumentNullException.ThrowIfNull(archiveReader);
        ArgumentNullException.ThrowIfNull(artifactStore);
        ArgumentNullException.ThrowIfNull(validator);
        ArgumentNullException.ThrowIfNull(auditWriter);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(limits);
        ArgumentNullException.ThrowIfNull(hostContractVersion);
        ArgumentNullException.ThrowIfNull(pluginRuntime);
        ArgumentNullException.ThrowIfNull(runningExecutions);
        ArgumentNullException.ThrowIfNull(executionOptions);

        _unitOfWorkFactory = unitOfWorkFactory;
        _archiveReader = archiveReader;
        _artifactStore = artifactStore;
        _validator = validator;
        _auditWriter = auditWriter;
        _timeProvider = timeProvider;
        _limits = limits;
        _hostContractVersion = hostContractVersion;
        _pluginRuntime = pluginRuntime;
        _runningExecutions = runningExecutions;
        _executionOptions = executionOptions;
    }

    public async Task<PluginOperation> InstallAsync(Stream package, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(package);

        Guid operationId = Guid.NewGuid();
        await CreateOperationAsync(operationId, OperationKind.Install, cancellationToken);
        string? stagingRoot = null;

        try
        {
            stagingRoot = await _artifactStore.CreateStagingDirectoryAsync(operationId, cancellationToken);
            await SetOperationStateAsync(
                operationId,
                OperationState.Running,
                Serialize(new InstallOperationPayload(stagingRoot, null, null)),
                cancellationToken);

            ExtractedPackage extracted =
                await _archiveReader.ExtractAsync(package, stagingRoot, _limits, cancellationToken);
            PackageValidationResult result = _validator.Validate(extracted, _hostContractVersion);

            // A published version is immutable: never mutate its record, even on a
            // rejected re-upload. Resolve it once for both the invalid and valid paths.
            PluginVersionRecord? existing = result.Manifest is null
                ? null
                : await GetExistingAsync(result.Manifest.Id, result.Manifest.Version, cancellationToken);
            bool alreadyPublished = existing is not null && existing.State.IsPublished();

            if (!result.IsValid || result.Manifest is null)
            {
                string reason = string.Join("; ", result.Errors);
                if (!alreadyPublished)
                {
                    await PersistRejectedAsync(result.Manifest, result.Errors, CancellationToken.None);
                }

                await FailOperationAsync(operationId, reason, CancellationToken.None);
                await DiscardStagingAsync(stagingRoot, CancellationToken.None);
                await AuditAsync("plugin.install.rejected", result.Manifest, reason, CancellationToken.None);
                return new PluginOperation(
                    operationId,
                    result.Manifest?.Id ?? string.Empty,
                    result.Manifest?.Version,
                    PluginOperationStatus.Failed,
                    reason);
            }

            PluginManifest manifest = result.Manifest;

            if (alreadyPublished)
            {
                string? conflict = string.Equals(existing!.ArtifactHash, manifest.ArtifactHash, StringComparison.Ordinal)
                    ? null
                    : $"Plugin version '{manifest.Id}' '{manifest.Version}' is already published and immutable.";
                await DiscardStagingAsync(stagingRoot, CancellationToken.None);
                stagingRoot = null;
                await CompleteConflictAsync(operationId, manifest, conflict, CancellationToken.None);
                return new PluginOperation(
                    operationId,
                    manifest.Id,
                    manifest.Version,
                    conflict is null ? PluginOperationStatus.Succeeded : PluginOperationStatus.Failed,
                    conflict);
            }

            DateTimeOffset installedAt = _timeProvider.GetUtcNow();
            await PersistValidatingAsync(manifest, stagingRoot, installedAt, cancellationToken);

            StagedArtifact staged = await _artifactStore.PromoteAsync(
                manifest.Id,
                manifest.Version,
                stagingRoot,
                manifest.ArtifactHash,
                cancellationToken);
            stagingRoot = null;

            await SetStagedAsync(manifest.Id, manifest.Version, staged.ArtifactPath, cancellationToken);
            await SetOperationStateAsync(
                operationId,
                OperationState.Succeeded,
                Serialize(new InstallOperationPayload(null, manifest.Id, manifest.Version.ToString())),
                cancellationToken);
            await AuditAsync("plugin.install", manifest, null, cancellationToken);

            return new PluginOperation(
                operationId,
                manifest.Id,
                manifest.Version,
                PluginOperationStatus.Succeeded);
        }
        catch (PackageValidationException exception)
        {
            await FailOperationAsync(operationId, exception.Message, CancellationToken.None);
            await DiscardStagingAsync(stagingRoot, CancellationToken.None);
            await _auditWriter.RecordAsync(
                Actor,
                "plugin.install.rejected",
                "package",
                exception.Message,
                CancellationToken.None);
            return new PluginOperation(
                operationId,
                string.Empty,
                null,
                PluginOperationStatus.Failed,
                exception.Message);
        }
        catch
        {
            await FailOperationAsync(operationId, "Install failed", CancellationToken.None);
            await DiscardStagingAsync(stagingRoot, CancellationToken.None);
            throw;
        }
    }

    public async Task<ValidationReport> ValidateAsync(
        string pluginId,
        Version version,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pluginId);
        ArgumentNullException.ThrowIfNull(version);

        await using (IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken))
        {
            _ = await unitOfWork.Plugins.GetVersionAsync(pluginId, version, cancellationToken)
                ?? throw new KeyNotFoundException($"Plugin version '{pluginId}' '{version}' was not found.");
        }

        ExtractedPackage? package = await _artifactStore.OpenAsync(pluginId, version, cancellationToken);
        if (package is null)
        {
            return ValidationReport.Invalid(pluginId, version, ["No retained artifact available to validate."]);
        }

        PackageValidationResult result = _validator.Validate(package, _hostContractVersion);
        await PersistRevalidationAsync(pluginId, version, result, cancellationToken);
        await _auditWriter.RecordAsync(
            Actor,
            "plugin.validate",
            $"{pluginId}:{version}",
            result.IsValid ? null : string.Join("; ", result.Errors),
            cancellationToken);

        return result.IsValid
            ? ValidationReport.Valid(pluginId, version, result.Warnings)
            : ValidationReport.Invalid(pluginId, version, result.Errors);
    }

    public async Task<IReadOnlyList<PluginDescriptor>> ListAsync(CancellationToken cancellationToken = default)
    {
        await using IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken);
        IReadOnlyList<string> pluginIds = await unitOfWork.Plugins.ListPluginIdsAsync(cancellationToken);

        List<PluginDescriptor> descriptors = [];
        foreach (string pluginId in pluginIds)
        {
            IReadOnlyList<PluginVersionRecord> versions =
                await unitOfWork.Plugins.ListVersionsAsync(pluginId, cancellationToken);
            PluginActivationRecord? activation =
                await unitOfWork.Plugins.GetActivationAsync(pluginId, cancellationToken);
            descriptors.Add(new PluginDescriptor(pluginId, activation?.Version, ResolveState(versions, activation)));
        }

        return descriptors;
    }

    public async Task<IReadOnlyList<PluginVersionDescriptor>> ListVersionsAsync(
        string pluginId,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pluginId);

        await using IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken);
        IReadOnlyList<PluginVersionRecord> versions =
            await unitOfWork.Plugins.ListVersionsAsync(pluginId, cancellationToken);

        return versions
            .Select(version => new PluginVersionDescriptor(
                version.PluginId,
                version.Version,
                version.State,
                version.InstalledAt,
                version.ValidatedAt))
            .ToList();
    }

    // Lifecycle transitions beyond install/validate belong to phase 3.
    public async Task<PluginOperation> ActivateAsync(
        string pluginId,
        Version version,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pluginId);
        ArgumentNullException.ThrowIfNull(version);

        return await ActivateCoreAsync(
            pluginId,
            version,
            OperationKind.Activate,
            "plugin.activate",
            cancellationToken);
    }

    public async Task<PluginOperation> DeactivateAsync(
        string pluginId,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pluginId);

        Guid operationId = Guid.NewGuid();
        await CreateLifecycleOperationAsync(
            operationId,
            OperationKind.Deactivate,
            new LifecycleOperationPayload(pluginId, null),
            cancellationToken);

        try
        {
            return await DeactivateCoreAsync(operationId, pluginId, cancellationToken);
        }
        catch (Exception exception)
        {
            await TryFailLifecycleOperationAsync(operationId, exception.Message, CancellationToken.None);
            await AuditAsync("plugin.deactivate", pluginId, null, exception.Message, CancellationToken.None);
            throw;
        }
    }

    private async Task<PluginOperation> DeactivateCoreAsync(
        Guid operationId,
        string pluginId,
        CancellationToken cancellationToken)
    {
        PluginActivationRecord? activation = await GetActivationAsync(pluginId, cancellationToken);
        if (activation is null)
        {
            await SetOperationStateAsync(
                operationId,
                OperationState.Running,
                Serialize(new LifecycleOperationPayload(pluginId, null)),
                cancellationToken);
            await SetOperationStateAsync(
                operationId,
                OperationState.Succeeded,
                Serialize(new LifecycleOperationPayload(pluginId, null) with { Error = "already inactive" }),
                cancellationToken);
            await AuditAsync("plugin.deactivate", pluginId, null, "already inactive", cancellationToken);
            return new PluginOperation(operationId, pluginId, null, PluginOperationStatus.Succeeded);
        }

        await SetOperationStateAsync(
            operationId,
            OperationState.Running,
            Serialize(new LifecycleOperationPayload(pluginId, activation.Version.ToString())),
            cancellationToken);

        await StopDispatchAsync(pluginId, activation.Version, cancellationToken);
        await DrainAsync(pluginId, activation.Version, cancellationToken);

        PluginUnloadResult unload = await _pluginRuntime.UnloadAsync(
            pluginId,
            activation.Version,
            CancellationToken.None);

        if (unload.Unloaded)
        {
            await SetVersionStateAsync(pluginId, activation.Version, PluginLifecycleState.Retired, cancellationToken);
            await SetOperationStateAsync(
                operationId,
                OperationState.Succeeded,
                Serialize(new LifecycleOperationPayload(pluginId, activation.Version.ToString())),
                cancellationToken);
            await AuditAsync("plugin.deactivate", pluginId, activation.Version, null, cancellationToken);
            return new PluginOperation(operationId, pluginId, activation.Version, PluginOperationStatus.Succeeded);
        }

        string error = "Deactivation unload incomplete: " + (unload.Reason ?? "unclean unload.");
        await SetUncleanUnloadAsync(pluginId, activation.Version, error, cancellationToken);
        await TryFailLifecycleOperationAsync(operationId, error, cancellationToken);
        await AuditAsync("plugin.deactivate", pluginId, activation.Version, error, cancellationToken);
        return new PluginOperation(operationId, pluginId, activation.Version, PluginOperationStatus.Failed, error);
    }

    public async Task<PluginOperation> RollbackAsync(
        string pluginId,
        Version targetVersion,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pluginId);
        ArgumentNullException.ThrowIfNull(targetVersion);

        return await ActivateCoreAsync(
            pluginId,
            targetVersion,
            OperationKind.Rollback,
            "plugin.rollback",
            cancellationToken);
    }

    public async Task<PluginOperation> RemoveAsync(
        string pluginId,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pluginId);

        Guid operationId = Guid.NewGuid();
        await CreateLifecycleOperationAsync(
            operationId,
            OperationKind.Remove,
            new LifecycleOperationPayload(pluginId, null),
            cancellationToken);

        try
        {
            return await RemoveCoreAsync(operationId, pluginId, cancellationToken);
        }
        catch (Exception exception)
        {
            await TryFailLifecycleOperationAsync(operationId, exception.Message, CancellationToken.None);
            await AuditAsync("plugin.remove", pluginId, null, exception.Message, CancellationToken.None);
            throw;
        }
    }

    private async Task<PluginOperation> RemoveCoreAsync(
        Guid operationId,
        string pluginId,
        CancellationToken cancellationToken)
    {
        PluginActivationRecord? activation = await GetActivationAsync(pluginId, cancellationToken);
        Version? target = activation?.Version;
        if (target is null)
        {
            IReadOnlyList<PluginVersionRecord> versions = await ListVersionsInternalAsync(pluginId, cancellationToken);
            target = versions.Count > 0 ? versions[^1].Version : null;
        }

        if (target is null)
        {
            return await FailLifecycleAsync(
                operationId,
                pluginId,
                null,
                $"Plugin '{pluginId}' has no versions to remove.",
                "plugin.remove.rejected",
                cancellationToken);
        }

        await SetOperationStateAsync(
            operationId,
            OperationState.Running,
            Serialize(new LifecycleOperationPayload(pluginId, target.ToString())),
            cancellationToken);

        if (activation is not null)
        {
            await StopDispatchAsync(pluginId, activation.Version, cancellationToken);
            await DrainAsync(pluginId, activation.Version, cancellationToken);
        }

        PluginUnloadResult unload = await _pluginRuntime.UnloadAsync(pluginId, target, CancellationToken.None);
        if (!unload.Unloaded)
        {
            string error = "Removal unload incomplete: " + (unload.Reason ?? "unclean unload.");
            await SetUncleanUnloadAsync(pluginId, target, error, cancellationToken);
            await TryFailLifecycleOperationAsync(operationId, error, cancellationToken);
            await AuditAsync("plugin.remove", pluginId, target, error, cancellationToken);
            return new PluginOperation(operationId, pluginId, target, PluginOperationStatus.Failed, error);
        }

        await MarkRemovedAsync(pluginId, target, cancellationToken);
        await SetOperationStateAsync(
            operationId,
            OperationState.Succeeded,
            Serialize(new LifecycleOperationPayload(pluginId, target.ToString())),
            cancellationToken);
        await AuditAsync("plugin.remove", pluginId, target, null, cancellationToken);
        return new PluginOperation(operationId, pluginId, target, PluginOperationStatus.Succeeded);
    }

    private async Task<PluginOperation> ActivateCoreAsync(
        string pluginId,
        Version version,
        OperationKind kind,
        string auditAction,
        CancellationToken cancellationToken)
    {
        Guid operationId = Guid.NewGuid();
        await CreateLifecycleOperationAsync(
            operationId,
            kind,
            new LifecycleOperationPayload(pluginId, version.ToString()),
            cancellationToken);

        PluginVersionRecord? record = await GetExistingAsync(pluginId, version, cancellationToken);
        if (record is null)
        {
            return await FailLifecycleAsync(
                operationId,
                pluginId,
                version,
                $"Plugin version '{pluginId}' '{version}' was not found.",
                auditAction + ".rejected",
                cancellationToken);
        }

        PluginActivationRecord? current = await GetActivationAsync(pluginId, cancellationToken);
        if (record.State == PluginLifecycleState.Active && current?.Version == version)
        {
            await SetOperationStateAsync(
                operationId,
                OperationState.Running,
                Serialize(new LifecycleOperationPayload(pluginId, version.ToString())),
                cancellationToken);
            await SetOperationStateAsync(
                operationId,
                OperationState.Succeeded,
                Serialize(new LifecycleOperationPayload(pluginId, version.ToString()) with { Error = "already active" }),
                cancellationToken);
            await AuditAsync(auditAction, pluginId, version, "already active", cancellationToken);
            return new PluginOperation(operationId, pluginId, version, PluginOperationStatus.Succeeded);
        }

        if (record.State is not (PluginLifecycleState.Staged or PluginLifecycleState.Retired))
        {
            return await FailLifecycleAsync(
                operationId,
                pluginId,
                version,
                $"Plugin version '{pluginId}' '{version}' is '{record.State}' and cannot be activated.",
                auditAction + ".rejected",
                cancellationToken);
        }

        if (string.IsNullOrWhiteSpace(record.ArtifactPath))
        {
            return await FailLifecycleAsync(
                operationId,
                pluginId,
                version,
                $"Plugin version '{pluginId}' '{version}' has no retained artifact.",
                auditAction + ".rejected",
                cancellationToken);
        }

        await SetVersionStateAsync(pluginId, version, PluginLifecycleState.Activating, cancellationToken);
        await SetOperationStateAsync(
            operationId,
            OperationState.Running,
            Serialize(new LifecycleOperationPayload(pluginId, version.ToString())),
            cancellationToken);

        LoadedPlugin loaded;
        try
        {
            loaded = await _pluginRuntime.LoadAsync(
                new PluginLoadRequest(
                    pluginId,
                    version,
                    record.ArtifactPath,
                    record.EntryAssembly,
                    record.EntryType),
                cancellationToken);
        }
        catch (Exception exception)
        {
            await _pluginRuntime.UnloadAsync(pluginId, version, CancellationToken.None);
            await SetVersionStateAsync(pluginId, version, PluginLifecycleState.Failed, cancellationToken, exception.Message);
            return await FailLifecycleAsync(
                operationId,
                pluginId,
                version,
                exception.Message,
                auditAction + ".rejected",
                cancellationToken,
                failOperation: false);
        }

        IReadOnlyList<string> definitionErrors = PluginDefinitionValidator.Validate(pluginId, version, loaded.Jobs);
        if (definitionErrors.Count > 0)
        {
            string reason = string.Join("; ", definitionErrors);
            await _pluginRuntime.UnloadAsync(pluginId, version, CancellationToken.None);
            await SetVersionStateAsync(pluginId, version, PluginLifecycleState.Failed, cancellationToken, reason);
            return await FailLifecycleAsync(
                operationId,
                pluginId,
                version,
                reason,
                auditAction + ".rejected",
                cancellationToken,
                failOperation: false);
        }

        try
        {
            await PublishActivationAsync(pluginId, version, loaded.Jobs, current, cancellationToken);
        }
        catch
        {
            await _pluginRuntime.UnloadAsync(pluginId, version, CancellationToken.None);
            await TrySetVersionStateAsync(pluginId, version, PluginLifecycleState.Failed, cancellationToken);
            await TryFailLifecycleOperationAsync(operationId, "Activation publication failed.", cancellationToken);
            throw;
        }

        string? uncleanReason = null;
        if (current is not null && current.Version != version)
        {
            await DrainAsync(pluginId, current.Version, cancellationToken);
            PluginUnloadResult previousUnload =
                await _pluginRuntime.UnloadAsync(pluginId, current.Version, CancellationToken.None);
            if (previousUnload.Unloaded)
            {
                await SetVersionStateAsync(pluginId, current.Version, PluginLifecycleState.Retired, cancellationToken);
            }
            else
            {
                uncleanReason = previousUnload.Reason ?? "unclean unload.";
                await SetUncleanUnloadAsync(pluginId, current.Version, uncleanReason, cancellationToken);
            }
        }

        await SetOperationStateAsync(
            operationId,
            OperationState.Succeeded,
            Serialize(new LifecycleOperationPayload(pluginId, version.ToString()) with { UncleanUnload = uncleanReason }),
            cancellationToken);
        await AuditAsync(auditAction, pluginId, version, uncleanReason, cancellationToken);
        return new PluginOperation(operationId, pluginId, version, PluginOperationStatus.Succeeded);
    }

    private static PluginLifecycleState ResolveState(
        IReadOnlyList<PluginVersionRecord> versions,
        PluginActivationRecord? activation)
    {
        if (activation is not null)
        {
            return versions.FirstOrDefault(version => version.Version == activation.Version)?.State
                ?? PluginLifecycleState.Failed;
        }

        return versions.Count > 0 ? versions[^1].State : PluginLifecycleState.Uploaded;
    }

    private async Task<PluginVersionRecord?> GetExistingAsync(
        string pluginId,
        Version version,
        CancellationToken cancellationToken)
    {
        await using IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken);
        return await unitOfWork.Plugins.GetVersionAsync(pluginId, version, cancellationToken);
    }

    private async Task CompleteConflictAsync(
        Guid operationId,
        PluginManifest manifest,
        string? conflict,
        CancellationToken cancellationToken)
    {
        if (conflict is null)
        {
            await SetOperationStateAsync(
                operationId,
                OperationState.Succeeded,
                Serialize(new InstallOperationPayload(null, manifest.Id, manifest.Version.ToString())),
                cancellationToken);
            await AuditAsync("plugin.install", manifest, "already published", cancellationToken);
            return;
        }

        await FailOperationAsync(operationId, conflict, cancellationToken);
        await _auditWriter.RecordAsync(
            Actor,
            "plugin.install.rejected",
            $"{manifest.Id}:{manifest.Version}",
            conflict,
            cancellationToken);
    }

    private async Task CreateOperationAsync(Guid operationId, OperationKind kind, CancellationToken cancellationToken)
    {
        DateTimeOffset now = _timeProvider.GetUtcNow();
        await using IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken);
        await unitOfWork.Operations.CreateAsync(
            new OperationRecord
            {
                OperationId = operationId,
                Kind = kind,
                Payload = Serialize(new InstallOperationPayload(null, null, null)),
                State = OperationState.Pending,
                CreatedAt = now,
                UpdatedAt = now,
            },
            cancellationToken);
        await unitOfWork.CommitAsync(cancellationToken);
    }

    private async Task SetOperationStateAsync(
        Guid operationId,
        OperationState state,
        string? payload,
        CancellationToken cancellationToken)
    {
        await using IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken);
        await unitOfWork.Operations.UpdateStateAsync(
            operationId,
            state,
            payload,
            _timeProvider.GetUtcNow(),
            cancellationToken);
        await unitOfWork.CommitAsync(cancellationToken);
    }

    private async Task FailOperationAsync(Guid operationId, string error, CancellationToken cancellationToken)
    {
        await using IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken);
        OperationRecord? operation = await unitOfWork.Operations.GetAsync(operationId, cancellationToken);
        if (operation is null || OperationTransitions.IsTerminal(operation.State))
        {
            return;
        }

        await unitOfWork.Operations.UpdateStateAsync(
            operationId,
            OperationState.Failed,
            Serialize(new InstallOperationPayload(null, null, null) with { Error = error }),
            _timeProvider.GetUtcNow(),
            cancellationToken);
        await unitOfWork.CommitAsync(cancellationToken);
    }

    private async Task PersistValidatingAsync(
        PluginManifest manifest,
        string stagingRoot,
        DateTimeOffset installedAt,
        CancellationToken cancellationToken)
    {
        await using IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken);
        await unitOfWork.Plugins.UpsertVersionAsync(
            BuildRecord(manifest, stagingRoot, installedAt) with
            {
                State = PluginLifecycleState.Validating,
                ValidatedAt = null,
            },
            cancellationToken);
        await unitOfWork.CommitAsync(cancellationToken);
    }

    private async Task PersistRejectedAsync(
        PluginManifest? manifest,
        IReadOnlyList<string> errors,
        CancellationToken cancellationToken)
    {
        if (manifest is null)
        {
            return;
        }

        DateTimeOffset now = _timeProvider.GetUtcNow();
        await using IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken);
        PluginVersionRecord? existing = await unitOfWork.Plugins.GetVersionAsync(
            manifest.Id, manifest.Version, cancellationToken);
        if (existing is not null && existing.State.IsPublished())
        {
            return;
        }

        await unitOfWork.Plugins.UpsertVersionAsync(
            BuildRecord(manifest, stagingRoot: null, now) with
            {
                State = PluginLifecycleState.Rejected,
                ValidatedAt = now,
                ValidationError = string.Join("; ", errors),
            },
            cancellationToken);
        await unitOfWork.CommitAsync(cancellationToken);
    }

    private async Task PersistRevalidationAsync(
        string pluginId,
        Version version,
        PackageValidationResult result,
        CancellationToken cancellationToken)
    {
        await using IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken);
        PluginVersionRecord? record = await unitOfWork.Plugins.GetVersionAsync(pluginId, version, cancellationToken);
        if (record is null || record.State is PluginLifecycleState.Active or PluginLifecycleState.Draining or PluginLifecycleState.Retired)
        {
            return;
        }

        await unitOfWork.Plugins.SetVersionStateAsync(
            pluginId,
            version,
            result.IsValid ? PluginLifecycleState.Staged : PluginLifecycleState.Rejected,
            result.IsValid ? null : string.Join("; ", result.Errors),
            _timeProvider.GetUtcNow(),
            cancellationToken);
        await unitOfWork.CommitAsync(cancellationToken);
    }

    private async Task SetStagedAsync(
        string pluginId,
        Version version,
        string artifactPath,
        CancellationToken cancellationToken)
    {
        await using IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken);
        await unitOfWork.Plugins.SetStagedAsync(pluginId, version, artifactPath, _timeProvider.GetUtcNow(), cancellationToken);
        await unitOfWork.CommitAsync(cancellationToken);
    }

    private async Task DiscardStagingAsync(string? stagingRoot, CancellationToken cancellationToken)
    {
        if (stagingRoot is null)
        {
            return;
        }

        await _artifactStore.DiscardStagingAsync(stagingRoot, cancellationToken);
    }

    private Task AuditAsync(string action, PluginManifest? manifest, string? details, CancellationToken cancellationToken)
    {
        string target = manifest is null ? "package" : $"{manifest.Id}:{manifest.Version}";
        return _auditWriter.RecordAsync(Actor, action, target, details, cancellationToken);
    }

    private static PluginVersionRecord BuildRecord(
        PluginManifest manifest,
        string? stagingRoot,
        DateTimeOffset installedAt) => new()
        {
            PluginId = manifest.Id,
            Version = manifest.Version,
            ContractVersion = manifest.ContractVersion.ToString(),
            EntryAssembly = manifest.EntryAssembly,
            EntryType = manifest.EntryType,
            ExecutionMode = manifest.ExecutionMode,
            ArtifactHash = manifest.ArtifactHash,
            State = PluginLifecycleState.Validating,
            InstalledAt = installedAt,
            ManifestJson = Encoding.UTF8.GetString(PluginManifestJson.ToCanonicalUtf8(manifest)),
            StagingPath = stagingRoot,
        };

    private static string Serialize<T>(T payload) => OperationPayloadCodec.Serialize(payload);

    private async Task CreateLifecycleOperationAsync(
        Guid operationId,
        OperationKind kind,
        LifecycleOperationPayload payload,
        CancellationToken cancellationToken)
    {
        DateTimeOffset now = _timeProvider.GetUtcNow();
        await using IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken);
        await unitOfWork.Operations.CreateAsync(
            new OperationRecord
            {
                OperationId = operationId,
                Kind = kind,
                Payload = Serialize(payload),
                State = OperationState.Pending,
                CreatedAt = now,
                UpdatedAt = now,
            },
            cancellationToken);
        await unitOfWork.CommitAsync(cancellationToken);
    }

    private async Task<PluginActivationRecord?> GetActivationAsync(string pluginId, CancellationToken cancellationToken)
    {
        await using IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken);
        return await unitOfWork.Plugins.GetActivationAsync(pluginId, cancellationToken);
    }

    private async Task<IReadOnlyList<PluginVersionRecord>> ListVersionsInternalAsync(
        string pluginId,
        CancellationToken cancellationToken)
    {
        await using IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken);
        return await unitOfWork.Plugins.ListVersionsAsync(pluginId, cancellationToken);
    }

    private async Task SetVersionStateAsync(
        string pluginId,
        Version version,
        PluginLifecycleState state,
        CancellationToken cancellationToken,
        string? validationError = null)
    {
        await using IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken);
        await unitOfWork.Plugins.SetVersionStateAsync(
            pluginId,
            version,
            state,
            validationError,
            _timeProvider.GetUtcNow(),
            cancellationToken);
        await unitOfWork.CommitAsync(cancellationToken);
    }

    private async Task MarkRemovedAsync(string pluginId, Version version, CancellationToken cancellationToken)
    {
        DateTimeOffset now = _timeProvider.GetUtcNow();
        await using IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken);
        await unitOfWork.Plugins.SetVersionStateAsync(
            pluginId,
            version,
            PluginLifecycleState.Removed,
            validationError: null,
            validatedAt: now,
            cancellationToken);
        await PublishScheduleChangesAsync(
            unitOfWork,
            await unitOfWork.Jobs.ListByPluginAsync(pluginId, cancellationToken),
            ScheduleChangeAction.Delete,
            now,
            cancellationToken);
        await unitOfWork.CommitAsync(cancellationToken);
    }

    private async Task TrySetVersionStateAsync(
        string pluginId,
        Version version,
        PluginLifecycleState state,
        CancellationToken cancellationToken)
    {
        try
        {
            await SetVersionStateAsync(pluginId, version, state, cancellationToken);
        }
        catch (KeyNotFoundException exception)
        {
            await _auditWriter.RecordAsync(
                Actor,
                "plugin.activate.cleanup.failed",
                $"{pluginId}:{version}",
                exception.Message,
                CancellationToken.None);
        }
    }

    private async Task SetUncleanUnloadAsync(
        string pluginId,
        Version version,
        string reason,
        CancellationToken cancellationToken)
    {
        await using IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken);
        await unitOfWork.Plugins.SetUncleanUnloadAsync(pluginId, version, reason, cancellationToken);
        await unitOfWork.CommitAsync(cancellationToken);
    }

    private async Task PublishActivationAsync(
        string pluginId,
        Version version,
        IReadOnlyCollection<JobDefinition> jobs,
        PluginActivationRecord? current,
        CancellationToken cancellationToken)
    {
        DateTimeOffset now = _timeProvider.GetUtcNow();
        await using IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken);

        if (current is not null && current.Version != version)
        {
            await unitOfWork.Plugins.SetVersionStateAsync(
                pluginId,
                current.Version,
                PluginLifecycleState.Draining,
                validationError: null,
                validatedAt: now,
                cancellationToken);
        }

        await unitOfWork.Plugins.SetVersionStateAsync(
            pluginId,
            version,
            PluginLifecycleState.Active,
            validationError: null,
            validatedAt: now,
            cancellationToken);
        await unitOfWork.Plugins.SetActivationAsync(
            new PluginActivationRecord
            {
                PluginId = pluginId,
                Version = version,
                ActivatedAt = now,
                ActivatedBy = Actor,
            },
            cancellationToken);

        foreach (JobDefinition job in jobs)
        {
            JobRecord? existing = await unitOfWork.Jobs.GetAsync(job.JobId, cancellationToken);
            JobRecord record = new()
            {
                Definition = job with { PluginVersion = version },
                ConfigurationRevision = (existing?.ConfigurationRevision ?? 0) + 1,
                UpdatedAt = now,
            };
            await unitOfWork.Jobs.UpsertAsync(record, cancellationToken);
            await PublishScheduleChangesAsync(
                unitOfWork,
                [record],
                existing is null ? ScheduleChangeAction.Create : ScheduleChangeAction.Update,
                now,
                cancellationToken);
        }

        // Definitions the new version no longer provides are removed in the same
        // publication, so their triggers converge away toward the registry.
        HashSet<string> provided = new(jobs.Select(job => job.JobId), StringComparer.Ordinal);
        IReadOnlyList<JobRecord> existingJobs = await unitOfWork.Jobs.ListByPluginAsync(pluginId, cancellationToken);
        foreach (JobRecord obsolete in existingJobs.Where(job => !provided.Contains(job.Definition.JobId)))
        {
            await unitOfWork.Jobs.DeleteAsync(obsolete.Definition.JobId, cancellationToken);
            await PublishScheduleChangesAsync(
                unitOfWork,
                [obsolete],
                ScheduleChangeAction.Delete,
                now,
                cancellationToken);
        }

        await unitOfWork.CommitAsync(cancellationToken);
    }

    private async Task StopDispatchAsync(string pluginId, Version version, CancellationToken cancellationToken)
    {
        DateTimeOffset now = _timeProvider.GetUtcNow();
        await using IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken);
        await unitOfWork.Plugins.SetVersionStateAsync(
            pluginId,
            version,
            PluginLifecycleState.Draining,
            validationError: null,
            validatedAt: now,
            cancellationToken);
        await unitOfWork.Plugins.ClearActivationAsync(pluginId, cancellationToken);
        await PublishScheduleChangesAsync(
            unitOfWork,
            await unitOfWork.Jobs.ListByPluginAsync(pluginId, cancellationToken),
            ScheduleChangeAction.Pause,
            now,
            cancellationToken);
        await unitOfWork.CommitAsync(cancellationToken);
    }

    private async Task DrainAsync(string pluginId, Version version, CancellationToken cancellationToken)
    {
        if (_executionOptions.DrainPolicy == DrainPolicy.Cancel)
        {
            foreach (IRunningExecution running in _runningExecutions.ListForPlugin(pluginId, version))
            {
                running.Cancel("Plugin version is being retired.");
            }
        }

        await _runningExecutions.WaitForPluginAsync(
            pluginId,
            version,
            _executionOptions.DrainTimeout,
            cancellationToken);
    }

    private async Task<PluginOperation> FailLifecycleAsync(
        Guid operationId,
        string pluginId,
        Version? version,
        string error,
        string auditAction,
        CancellationToken cancellationToken,
        bool failOperation = true)
    {
        if (failOperation)
        {
            await TryFailLifecycleOperationAsync(operationId, error, cancellationToken);
        }

        await AuditAsync(
            auditAction,
            pluginId,
            version,
            error,
            cancellationToken);
        return new PluginOperation(operationId, pluginId, version, PluginOperationStatus.Failed, error);
    }

    private async Task TryFailLifecycleOperationAsync(Guid operationId, string error, CancellationToken cancellationToken)
    {
        await using IRegistryUnitOfWork unitOfWork = await _unitOfWorkFactory.BeginAsync(cancellationToken);
        OperationRecord? operation = await unitOfWork.Operations.GetAsync(operationId, cancellationToken);
        if (operation is null || OperationTransitions.IsTerminal(operation.State))
        {
            return;
        }

        await unitOfWork.Operations.UpdateStateAsync(
            operationId,
            OperationState.Failed,
            Serialize(new LifecycleOperationPayload(string.Empty, null) with { Error = error }),
            _timeProvider.GetUtcNow(),
            cancellationToken);
        await unitOfWork.CommitAsync(cancellationToken);
    }

    private Task AuditAsync(
        string action,
        string pluginId,
        Version? version,
        string? details,
        CancellationToken cancellationToken)
    {
        string target = version is null ? pluginId : $"{pluginId}:{version}";
        return _auditWriter.RecordAsync(Actor, action, target, details, cancellationToken);
    }

    private static async Task PublishScheduleChangesAsync(
        IRegistryUnitOfWork unitOfWork,
        IReadOnlyList<JobRecord> jobs,
        ScheduleChangeAction action,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        foreach (JobRecord job in jobs)
        {
            await unitOfWork.Operations.CreateAsync(
                ScheduleChangeOutbox.Create(Guid.NewGuid(), job, action, now),
                cancellationToken);
        }
    }
}

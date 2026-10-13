using System.IO.Abstractions;
using Microsoft.AspNetCore.Http.Features;
using Scheduler.Application.Execution;
using Scheduler.Application.JobManagement;
using Scheduler.Application.Maintenance;
using Scheduler.Application.Observability;
using Scheduler.Application.Packaging;
using Scheduler.Application.Persistence;
using Scheduler.Application.PluginManagement;
using Scheduler.Application.Reconciliation;
using Scheduler.Application.Secrets;
using Scheduler.Application.Security;
using Scheduler.Contracts;
using Scheduler.Contracts.Execution;
using Scheduler.Contracts.Jobs;
using Scheduler.Infrastructure.Maintenance;
using Scheduler.Infrastructure.Observability;
using Scheduler.Infrastructure.Packaging;
using Scheduler.Infrastructure.Persistence;
using Scheduler.Infrastructure.Scheduling;
using Scheduler.Infrastructure.Secrets;
using Scheduler.Infrastructure.Security;
using Scheduler.Runtime.InProcess.AssemblyLoading;
using Scheduler.Runtime.InProcess.Execution;
using Scheduler.Host;

const long MultipartBodyLengthLimit = 512L * 1024 * 1024;

var builder = WebApplication.CreateBuilder(args);

IFileSystem fileSystem = new FileSystem();

builder.Logging.ClearProviders();
builder.Logging.AddJsonConsole(options => options.IncludeScopes = true);
builder.Logging.AddProvider(new SimpleFileLoggerProvider(
    ResolveLogsRoot(packagingLogsRoot: builder.Configuration["JobScheduler:LogsRoot"] ?? "logs", builder.Environment.ContentRootPath),
    fileSystem));

builder.Services.AddHealthChecks();
builder.Services.Configure<FormOptions>(options => options.MultipartBodyLengthLimit = MultipartBodyLengthLimit);

PersistenceOptions persistenceOptions = new()
{
    DatabasePath = builder.Configuration["JobScheduler:DatabasePath"] ?? "data/jobscheduler.db",
    BaseDirectory = builder.Environment.ContentRootPath,
};
PackagingOptions packagingOptions = new()
{
    ArtifactsRoot = builder.Configuration["JobScheduler:ArtifactsRoot"] ?? "data/artifacts",
    StagingRoot = builder.Configuration["JobScheduler:StagingRoot"] ?? "data/staging",
    PublicKeyPath = builder.Configuration["JobScheduler:PackagePublicKeyPath"] ?? "keys/package-signing.pub.pem",
    DataRoot = builder.Configuration["JobScheduler:DataRoot"] ?? "data",
    LogsRoot = builder.Configuration["JobScheduler:LogsRoot"] ?? "logs",
    BackupRoot = builder.Configuration["JobScheduler:BackupRoot"] ?? "data/backups",
    BaseDirectory = builder.Environment.ContentRootPath,
};
ExecutionOptions executionOptions = new()
{
    GlobalConcurrencyLimit = builder.Configuration.GetValue("JobScheduler:GlobalConcurrencyLimit", 8),
    DrainTimeout = builder.Configuration.GetValue("JobScheduler:GracefulShutdownDrainTimeout", TimeSpan.FromMinutes(1)),
    DrainPolicy = builder.Configuration.GetValue("JobScheduler:DefaultDrainPolicy", DrainPolicy.Wait),
};
ScheduleOptions scheduleOptions = new()
{
    SchedulerName = builder.Configuration["JobScheduler:SchedulerName"] ?? "scheduler",
    UsePersistentStore = builder.Configuration.GetValue("JobScheduler:UsePersistentStore", true),
};
ObservabilityOptions observabilityOptions = new()
{
    RetainedLogs = builder.Configuration.GetValue("JobScheduler:RetainedLogs", 500),
    ExecutionHeartbeat = builder.Configuration.GetValue("JobScheduler:ExecutionHeartbeat", TimeSpan.FromMinutes(30)),
    StuckCheckInterval = builder.Configuration.GetValue("JobScheduler:StuckCheckInterval", TimeSpan.FromMinutes(1)),
};
SecretStoreOptions secretStoreOptions = new()
{
    StoreRoot = builder.Configuration["JobScheduler:SecretStore:StoreRoot"] ?? "data/secrets",
    KeyPath = builder.Configuration["JobScheduler:SecretStore:KeyPath"] ?? "keys/secret-store.key",
    BaseDirectory = builder.Environment.ContentRootPath,
    WritableRoots = packagingOptions.WritableRoots,
};
ManagementApiOptions managementApiOptions = ReadManagementApiOptions(builder.Configuration);
managementApiOptions.Validate();

int managementPort = builder.Configuration.GetValue("JobScheduler:ManagementApi:Port", 5080);
builder.WebHost.ConfigureKestrel(options =>
{
    if (managementApiOptions.AllowRemoteAccess)
    {
        options.ListenAnyIP(managementPort);
    }
    else
    {
        options.ListenLocalhost(managementPort);
    }
});

builder.Services.Configure<HostOptions>(
    options => options.ShutdownTimeout = executionOptions.DrainTimeout + TimeSpan.FromSeconds(5));

SqliteConnectionFactory connectionFactory = new(persistenceOptions, fileSystem);

builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton(fileSystem);
builder.Services.AddSingleton(persistenceOptions);
builder.Services.AddSingleton(packagingOptions);
builder.Services.AddSingleton(packagingOptions.ToLimits());
builder.Services.AddSingleton(SchedulerContract.CurrentVersion);
builder.Services.AddSingleton(executionOptions);
builder.Services.AddSingleton(secretStoreOptions);
builder.Services.AddSingleton(managementApiOptions);
builder.Services.AddSingleton<ISqliteConnectionFactory>(connectionFactory);
builder.Services.AddSingleton<IDatabaseInitializer>(services =>
    new SqliteDatabaseInitializer(
        services.GetRequiredService<ISqliteConnectionFactory>(),
        SchemaMigrations.All));
builder.Services.AddSingleton<IRegistryUnitOfWorkFactory, SqliteRegistryUnitOfWorkFactory>();
builder.Services.AddSingleton<IAuditWriter, AuditWriter>();
builder.Services.AddSingleton<IPackageArchiveReader, ZipPackageArchiveReader>();
builder.Services.AddSingleton<IPackageSignatureVerifier, PackageSignatureVerifier>();
builder.Services.AddSingleton<IArtifactStore, FileSystemArtifactStore>();
builder.Services.AddSingleton<PackageValidator>();
builder.Services.AddSingleton<ISecretValueStore, FileSecretValueStore>();
builder.Services.AddSingleton<SecretAdminService>();
builder.Services.AddSingleton<IApiAuthenticator, SecretBackedApiAuthenticator>();
builder.Services.AddSingleton<IBackupService, FileSystemBackupService>();
builder.Services.AddSingleton<LifecycleRequestCoordinator>();
builder.Services.AddSingleton<ShutdownSignal>();

builder.Services.AddSingleton<IPluginRuntime, InProcessPluginRuntime>();
builder.Services.AddSingleton<IRunningExecutionRegistry, RunningExecutionRegistry>();
builder.Services.AddSingleton<ConcurrencyGate>();
builder.Services.AddSingleton<RetryPolicyEvaluator>();
builder.Services.AddSingleton<ExecutionDrainer>();
builder.Services.AddSingleton<ISecretProviderFactory, RegistrySecretProviderFactory>();
builder.Services.AddSingleton<IExecutionBackend, InProcessExecutionBackend>();
builder.Services.AddSingleton<ExecutionRunner>();
builder.Services.AddSingleton<IDispatcher, Dispatcher>();
builder.Services.AddSingleton<IJobManager, JobManager>();
builder.Services.AddSingleton<IPluginManager, PluginManager>();

builder.Services.AddSchedulerScheduling(connectionFactory.DatabasePath, scheduleOptions);
builder.Services.AddSchedulerObservability(observabilityOptions);

builder.Services.AddHostedService<StuckExecutionMonitorService>();
builder.Services.AddHostedService<ShutdownDrainService>();

var app = builder.Build();

if (managementApiOptions.AllowRemoteAccess)
{
    HostLog.RemoteAccessEnabled(app.Logger);
}

await using (AsyncServiceScope scope = app.Services.CreateAsyncScope())
{
    IDatabaseInitializer initializer = scope.ServiceProvider.GetRequiredService<IDatabaseInitializer>();
    await initializer.InitializeAsync();

    LifecycleRequestCoordinator lifecycleRequests = scope.ServiceProvider.GetRequiredService<LifecycleRequestCoordinator>();
    await lifecycleRequests.RecoverInterruptedAsync();

    SigningKeyPathGuard.EnsureOutsideWritableRoots(packagingOptions, scope.ServiceProvider.GetRequiredService<IFileSystem>());
    SecretKeyPathGuard.EnsureOutsideWritableRoots(secretStoreOptions, scope.ServiceProvider.GetRequiredService<IFileSystem>());

    await BootstrapCredentialsAsync(
        scope.ServiceProvider.GetRequiredService<ISecretValueStore>(),
        managementApiOptions,
        builder.Configuration["SCHEDULER_BOOTSTRAP_MANAGEMENT_TOKEN"]);

    IApiAuthenticator authenticator = scope.ServiceProvider.GetRequiredService<IApiAuthenticator>();
    if (managementApiOptions.Enabled)
    {
        await authenticator.InitializeAsync();
    }

    IArtifactStore artifactStore = scope.ServiceProvider.GetRequiredService<IArtifactStore>();
    await artifactStore.ClearStagingAsync();

    IRegistryUnitOfWorkFactory unitOfWorkFactory = scope.ServiceProvider.GetRequiredService<IRegistryUnitOfWorkFactory>();
    DateTimeOffset startupNow = TimeProvider.System.GetUtcNow();
    await using IRegistryUnitOfWork unitOfWork = await unitOfWorkFactory.BeginAsync();
    int interrupted = await unitOfWork.Executions.MarkRunningAsInterruptedAsync(startupNow);
    if (interrupted > 0)
    {
        await unitOfWork.Audit.WriteAsync(new AuditEntry
        {
            Timestamp = startupNow,
            Actor = "host",
            Action = "execution.recovered",
            Target = "executions",
            Details = $"interrupted={interrupted}",
        });
    }

    await unitOfWork.CommitAsync();

    IExecutionLogStore logStore = scope.ServiceProvider.GetRequiredService<IExecutionLogStore>();
    await logStore.TrimAsync(observabilityOptions.RetainedLogs);
}

app.UseMiddleware<ManagementApiAuthenticationMiddleware>();

app.MapHealthChecks("/healthz");

app.MapGet("/api/plugins", async (IPluginManager manager, CancellationToken cancellationToken) =>
    Results.Ok(await manager.ListAsync(cancellationToken)))
    .RequireScope(AuthorizationScope.Read);

app.MapPost("/api/plugins", async (
    HttpRequest request,
    IPluginManager manager,
    LifecycleRequestCoordinator coordinator,
    CancellationToken cancellationToken) =>
{
    if (!request.HasFormContentType)
    {
        return Results.BadRequest(new { error = "A multipart/form-data package upload is required." });
    }

    Guid? operationId = ReadOperationId(request);
    IFormCollection form = await request.ReadFormAsync(cancellationToken);
    IFormFile? file = form.Files.Count > 0 ? form.Files[0] : null;
    if (file is null || file.Length == 0)
    {
        return Results.BadRequest(new { error = "A non-empty package file is required." });
    }

    // The upload stream cannot be replayed; an idempotent install records its
    // result on first use and replays from the operation record thereafter.
    return await RunLifecycleAsync(
        token => InstallAsync(manager, file, token),
        operationId,
        "install",
        file.FileName,
        coordinator,
        cancellationToken);
}).RequireScope(AuthorizationScope.Install);

app.MapPost("/api/plugins/{id}/{version}/validate", async (
    string id,
    string version,
    IPluginManager manager,
    CancellationToken cancellationToken) =>
{
    if (!Version.TryParse(version, out Version? parsed))
    {
        return Results.BadRequest(new { error = $"'{version}' is not a valid version." });
    }

    try
    {
        ValidationReport report = await manager.ValidateAsync(id, parsed, cancellationToken);
        return Results.Ok(report);
    }
    catch (KeyNotFoundException exception)
    {
        return Results.NotFound(new { error = exception.Message });
    }
}).RequireScope(AuthorizationScope.Validate);

app.MapGet("/api/plugins/{id}/versions", async (
    string id,
    IPluginManager manager,
    CancellationToken cancellationToken) =>
    Results.Ok(await manager.ListVersionsAsync(id, cancellationToken)))
    .RequireScope(AuthorizationScope.Read);

app.MapPost("/api/plugins/{id}/{version}/activate", async (
    string id,
    string version,
    HttpRequest request,
    IPluginManager manager,
    LifecycleRequestCoordinator coordinator,
    CancellationToken cancellationToken) =>
{
    if (!Version.TryParse(version, out Version? parsed))
    {
        return Results.BadRequest(new { error = $"'{version}' is not a valid version." });
    }

    Guid? operationId = ReadOperationId(request);
    return await RunLifecycleAsync(
        token => manager.ActivateAsync(id, parsed, token),
        operationId,
        "activate",
        $"{id}:{parsed}",
        coordinator,
        cancellationToken);
}).RequireScope(AuthorizationScope.Activate).AddEndpointFilter<ReconcileAfterLifecycleFilter>();

app.MapPost("/api/plugins/{id}/deactivate", async (
    string id,
    HttpRequest request,
    IPluginManager manager,
    LifecycleRequestCoordinator coordinator,
    CancellationToken cancellationToken) =>
{
    Guid? operationId = ReadOperationId(request);
    return await RunLifecycleAsync(
        token => manager.DeactivateAsync(id, token),
        operationId,
        "deactivate",
        id,
        coordinator,
        cancellationToken);
}).RequireScope(AuthorizationScope.Deactivate).AddEndpointFilter<ReconcileAfterLifecycleFilter>();

app.MapPost("/api/plugins/{id}/{version}/rollback", async (
    string id,
    string version,
    HttpRequest request,
    IPluginManager manager,
    LifecycleRequestCoordinator coordinator,
    CancellationToken cancellationToken) =>
{
    if (!Version.TryParse(version, out Version? parsed))
    {
        return Results.BadRequest(new { error = $"'{version}' is not a valid version." });
    }

    Guid? operationId = ReadOperationId(request);
    return await RunLifecycleAsync(
        token => manager.RollbackAsync(id, parsed, token),
        operationId,
        "rollback",
        $"{id}:{parsed}",
        coordinator,
        cancellationToken);
}).RequireScope(AuthorizationScope.Rollback).AddEndpointFilter<ReconcileAfterLifecycleFilter>();

app.MapPost("/api/plugins/{id}/remove", async (
    string id,
    HttpRequest request,
    IPluginManager manager,
    LifecycleRequestCoordinator coordinator,
    CancellationToken cancellationToken) =>
{
    Guid? operationId = ReadOperationId(request);
    return await RunLifecycleAsync(
        token => manager.RemoveAsync(id, token),
        operationId,
        "remove",
        id,
        coordinator,
        cancellationToken);
}).RequireScope(AuthorizationScope.Remove).AddEndpointFilter<ReconcileAfterLifecycleFilter>();

app.MapGet("/api/jobs", async (IJobManager jobs, CancellationToken cancellationToken) =>
    Results.Ok(await jobs.ListAsync(cancellationToken)))
    .RequireScope(AuthorizationScope.Read);

app.MapGet("/api/jobs/{id}", async (string id, IJobManager jobs, CancellationToken cancellationToken) =>
{
    JobDefinition? definition = await jobs.GetAsync(id, cancellationToken);
    return definition is null ? Results.NotFound(new { id }) : Results.Ok(definition);
}).RequireScope(AuthorizationScope.Read);

app.MapPut("/api/jobs/{id}", async (
    string id,
    JobDefinition definition,
    IJobManager jobs,
    CancellationToken cancellationToken) =>
{
    if (!string.Equals(id, definition.JobId, StringComparison.Ordinal))
    {
        return Results.BadRequest(new { error = "The route id and definition jobId must match." });
    }

    try
    {
        return Results.Ok(await jobs.UpdateAsync(definition, cancellationToken));
    }
    catch (JobValidationException exception)
    {
        return Results.BadRequest(new { error = exception.Message, exception.Errors });
    }
}).RequireScope(AuthorizationScope.Activate).AddEndpointFilter<ReconcileAfterLifecycleFilter>();

app.MapPost("/api/jobs/{id}/run", async (
    string id,
    IJobManager jobs,
    CancellationToken cancellationToken) =>
{
    try
    {
        Guid executionId = await jobs.RunNowAsync(id, cancellationToken);
        return Results.Ok(new { executionId });
    }
    catch (DispatchRejectedException exception)
    {
        return Results.Json(
            new { error = exception.Message, reason = exception.Reason.ToString() },
            statusCode: StatusCodes.Status409Conflict);
    }
    catch (KeyNotFoundException exception)
    {
        return Results.NotFound(new { error = exception.Message, reason = nameof(ExecutionRejectionReason.NotFound) });
    }
    catch (InvalidOperationException exception)
    {
        return Results.Json(new { error = exception.Message }, statusCode: StatusCodes.Status409Conflict);
    }
}).RequireScope(AuthorizationScope.ManualRun);

app.MapGet("/api/executions", async (
    string? jobId,
    string? status,
    DateTimeOffset? since,
    DateTimeOffset? until,
    int? limit,
    IRegistryUnitOfWorkFactory unitOfWorkFactory,
    ObservabilityOptions observability,
    CancellationToken cancellationToken) =>
{
    JobExecutionStatus? parsedStatus = null;
    if (!string.IsNullOrWhiteSpace(status))
    {
        if (!Enum.TryParse(status, ignoreCase: true, out JobExecutionStatus value) || !Enum.IsDefined(value))
        {
            return Results.BadRequest(new { error = $"'{status}' is not a valid execution status." });
        }

        parsedStatus = value;
    }

    ExecutionFilter filter = new()
    {
        JobId = jobId,
        Status = parsedStatus,
        Since = since,
        Until = until,
        Limit = Math.Clamp(limit ?? observability.ExecutionListLimit, 1, observability.ExecutionListLimit),
    };

    await using IRegistryUnitOfWork unitOfWork = await unitOfWorkFactory.BeginAsync(cancellationToken);
    return Results.Ok(await unitOfWork.Executions.ListAsync(filter, cancellationToken));
}).RequireScope(AuthorizationScope.Read);

app.MapGet("/api/jobs/{id}/executions", async (
    string id,
    IRegistryUnitOfWorkFactory unitOfWorkFactory,
    CancellationToken cancellationToken) =>
{
    await using IRegistryUnitOfWork unitOfWork = await unitOfWorkFactory.BeginAsync(cancellationToken);
    return Results.Ok(await unitOfWork.Executions.ListByJobAsync(id, cancellationToken));
}).RequireScope(AuthorizationScope.Read);

app.MapGet("/api/executions/summary", async (
    string? window,
    IExecutionSummaryService summary,
    CancellationToken cancellationToken) =>
{
    TimeSpan? parsedWindow = null;
    if (!string.IsNullOrWhiteSpace(window))
    {
        if (!DurationParser.TryParse(window, out TimeSpan value))
        {
            return Results.BadRequest(new { error = $"'{window}' is not a valid window (e.g. 90s, 30m, 24h, 7d)." });
        }

        parsedWindow = value;
    }

    return Results.Ok(await summary.GetSummaryAsync(parsedWindow, cancellationToken));
}).RequireScope(AuthorizationScope.Read);

app.MapGet("/api/executions/{id:guid}", async (
    Guid id,
    IRegistryUnitOfWorkFactory unitOfWorkFactory,
    CancellationToken cancellationToken) =>
{
    await using IRegistryUnitOfWork unitOfWork = await unitOfWorkFactory.BeginAsync(cancellationToken);
    ExecutionRecord? execution = await unitOfWork.Executions.GetAsync(id, cancellationToken);
    return execution is null ? Results.NotFound(new { id }) : Results.Ok(execution);
}).RequireScope(AuthorizationScope.Read);

app.MapGet("/api/executions/{id:guid}/logs", async (
    Guid id,
    IExecutionLogStore logs,
    IRegistryUnitOfWorkFactory unitOfWorkFactory,
    CancellationToken cancellationToken) =>
{
    await using IRegistryUnitOfWork unitOfWork = await unitOfWorkFactory.BeginAsync(cancellationToken);
    ExecutionRecord? execution = await unitOfWork.Executions.GetAsync(id, cancellationToken);
    if (execution is null)
    {
        return Results.NotFound(new { id });
    }

    return Results.Ok(await logs.ReadAsync(id, cancellationToken));
}).RequireScope(AuthorizationScope.Read);

app.MapPost("/api/executions/{id:guid}/cancel", async (
    Guid id,
    IDispatcher dispatcher,
    CancellationToken cancellationToken) =>
{
    bool cancelled = await dispatcher.CancelAsync(id, "Requested via API", cancellationToken);
    return cancelled ? Results.Ok(new { executionId = id, status = "cancelling" }) : Results.NotFound(new { id });
}).RequireScope(AuthorizationScope.ManualRun);

app.MapGet("/api/audit", async (
    string? actor,
    string? action,
    string? target,
    DateTimeOffset? since,
    int? limit,
    IRegistryUnitOfWorkFactory unitOfWorkFactory,
    ObservabilityOptions observability,
    CancellationToken cancellationToken) =>
{
    AuditFilter filter = new()
    {
        Actor = actor,
        Action = action,
        Target = target,
        Since = since,
        Limit = Math.Clamp(limit ?? 100, 1, observability.ExecutionListLimit),
    };

    await using IRegistryUnitOfWork unitOfWork = await unitOfWorkFactory.BeginAsync(cancellationToken);
    return Results.Ok(await unitOfWork.Audit.ListAsync(filter, cancellationToken));
}).RequireScope(AuthorizationScope.Read);

app.MapGet("/api/health", async (IHealthReportService health, CancellationToken cancellationToken) =>
{
    HealthReport report = await health.GetHealthAsync(cancellationToken);
    return report.Healthy
        ? Results.Ok(report)
        : Results.Json(report, statusCode: StatusCodes.Status503ServiceUnavailable);
}).RequireScope(AuthorizationScope.Read);

app.MapPost("/api/secrets", async (
    SecretWrite body,
    HttpContext context,
    SecretAdminService secrets,
    CancellationToken cancellationToken) =>
{
    string actor = Actor(context);
    await secrets.SetValueAsync(body.Reference, body.Value, actor, cancellationToken);
    return Results.Ok(new { reference = body.Reference, status = "set" });
}).RequireScope(AuthorizationScope.SecretAdmin);

app.MapGet("/api/secrets", async (SecretAdminService secrets, CancellationToken cancellationToken) =>
    Results.Ok(await secrets.ListReferencesAsync(cancellationToken)))
    .RequireScope(AuthorizationScope.SecretAdmin);

app.MapDelete("/api/secrets/{reference}", async (
    string reference,
    HttpContext context,
    SecretAdminService secrets,
    CancellationToken cancellationToken) =>
{
    await secrets.RemoveValueAsync(reference, Actor(context), cancellationToken);
    return Results.Ok(new { reference, status = "removed" });
}).RequireScope(AuthorizationScope.SecretAdmin);

app.MapGet("/api/secrets/grants", async (
    string pluginId,
    SecretAdminService secrets,
    CancellationToken cancellationToken) =>
    Results.Ok(await secrets.ListGrantsAsync(pluginId, cancellationToken)))
    .RequireScope(AuthorizationScope.SecretAdmin);

app.MapPost("/api/secrets/grants", async (
    SecretGrantRequest body,
    HttpContext context,
    SecretAdminService secrets,
    CancellationToken cancellationToken) =>
{
    await secrets.GrantAsync(body.PluginId, body.JobId, body.SecretReference, Actor(context), cancellationToken);
    return Results.Ok(new { body.PluginId, body.JobId, body.SecretReference, status = "granted" });
}).RequireScope(AuthorizationScope.SecretAdmin);

app.MapDelete("/api/secrets/grants", async (
    string pluginId,
    string? jobId,
    string secretReference,
    HttpContext context,
    SecretAdminService secrets,
    CancellationToken cancellationToken) =>
{
    bool removed = await secrets.RevokeAsync(pluginId, jobId, secretReference, Actor(context), cancellationToken);
    return Results.Ok(new { pluginId, jobId, secretReference, status = removed ? "revoked" : "absent" });
}).RequireScope(AuthorizationScope.SecretAdmin);

app.MapPost("/api/maintenance/backup", async (
    BackupRequest body,
    IBackupService backup,
    CancellationToken cancellationToken) =>
{
    BackupResult result = await backup.CreateAsync(body.Destination, cancellationToken);
    return Results.Ok(result);
}).RequireScope(AuthorizationScope.SecretAdmin);

app.Run();

static async Task<PluginOperation> InstallAsync(IPluginManager manager, IFormFile file, CancellationToken cancellationToken)
{
    await using Stream stream = file.OpenReadStream();
    return await manager.InstallAsync(stream, cancellationToken);
}

static async Task<IResult> RunLifecycleAsync(
    Func<CancellationToken, Task<PluginOperation>> operation,
    Guid? operationId,
    string action,
    string target,
    LifecycleRequestCoordinator coordinator,
    CancellationToken cancellationToken)
{
    if (operationId is null)
    {
        return LifecycleResult(await operation(cancellationToken));
    }

    try
    {
        PluginOperation result = await coordinator.RunAsync(operationId.Value, action, target, operation, cancellationToken);
        return LifecycleResult(result);
    }
    catch (IdempotentOperationInProgressException exception)
    {
        return Results.Json(
            new { error = exception.Message, reason = "in-progress" },
            statusCode: StatusCodes.Status409Conflict);
    }
    catch (IdempotentOperationConflictException exception)
    {
        return Results.Json(
            new { error = exception.Message, reason = "conflict" },
            statusCode: StatusCodes.Status409Conflict);
    }
}

static IResult LifecycleResult(PluginOperation operation) =>
    operation.Status == PluginOperationStatus.Succeeded
        ? Results.Ok(operation)
        : Results.Json(operation, statusCode: StatusCodes.Status422UnprocessableEntity);

static Guid? ReadOperationId(HttpRequest request)
{
    string? raw = request.Headers["X-Operation-Id"];
    if (string.IsNullOrWhiteSpace(raw))
    {
        return null;
    }

    return Guid.TryParse(raw, out Guid operationId)
        ? operationId
        : throw new BadHttpRequestException("The X-Operation-Id header must be a GUID.");
}

static string Actor(HttpContext context) =>
    ManagementApiAuthenticationMiddleware.Principal(context)?.Name ?? "unknown";

/// <summary>
/// Seeds configured credential references that have no stored value from the
/// runtime bootstrap environment variable. The token value is injected at
/// runtime (never committed); once stored, the reference resolves from the
/// encrypted store and this bootstrap is a no-op.
/// </summary>
static async Task BootstrapCredentialsAsync(
    ISecretValueStore store,
    ManagementApiOptions options,
    string? bootstrapToken)
{
    // A single bootstrap value only makes sense for a single credential; with more
    // than one, each must be provisioned distinctly to avoid collapsing principals.
    if (string.IsNullOrEmpty(bootstrapToken) || options.Credentials.Count != 1)
    {
        return;
    }

    ApiCredentialOptions credential = options.Credentials[0];
    if (await store.GetAsync(credential.Reference) is null)
    {
        await store.SetAsync(credential.Reference, bootstrapToken);
    }
}

static ManagementApiOptions ReadManagementApiOptions(IConfiguration configuration)
{
    IConfigurationSection section = configuration.GetSection("JobScheduler:ManagementApi");
    List<ApiCredentialOptions> credentials = [];
    foreach (IConfigurationSection credential in section.GetSection("Credentials").GetChildren())
    {
        string? reference = credential["Reference"];
        if (string.IsNullOrWhiteSpace(reference))
        {
            continue;
        }

        List<AuthorizationScope> scopes = [];
        foreach (IConfigurationSection scope in credential.GetSection("Scopes").GetChildren())
        {
            string? name = scope.Value;
            if (string.IsNullOrWhiteSpace(name))
            {
                continue;
            }

            if (!AuthorizationScopeNames.TryParse(name, out AuthorizationScope parsed))
            {
                throw new InvalidOperationException(
                    $"Management API credential '{reference}' declares unknown scope '{name}'.");
            }

            scopes.Add(parsed);
        }

        credentials.Add(new ApiCredentialOptions { Reference = reference, Scopes = scopes });
    }

    return new ManagementApiOptions
    {
        Enabled = section.GetValue("Enabled", true),
        AllowRemoteAccess = section.GetValue("AllowRemoteAccess", false),
        Credentials = credentials,
    };
}

static string ResolveLogsRoot(string packagingLogsRoot, string contentRoot) =>
    Path.IsPathRooted(packagingLogsRoot)
        ? packagingLogsRoot
        : Path.GetFullPath(Path.Combine(contentRoot, packagingLogsRoot));

public partial class Program;

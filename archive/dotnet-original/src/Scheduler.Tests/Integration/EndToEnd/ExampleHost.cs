using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using Microsoft.Data.Sqlite;
using Scheduler.Cli;
using Scheduler.Tests.Support;

namespace Scheduler.Tests.Integration.EndToEnd;

/// <summary>
/// Runs the real <c>Scheduler.Host</c> as a child process against throwaway
/// directories, keys, and a loopback port, and drives it through the real
/// management API. No test-only host is used: this is the production
/// composition root. The admin credential is provisioned through the Phase 6
/// bootstrap environment variable.
/// </summary>
internal sealed class ExampleHost : IAsyncDisposable
{
    public const string AdminToken = "example-admin-token";

    private readonly object _outputLock = new();
    private readonly StringBuilder _output = new();
    private readonly Process _process;
    private readonly HttpClient _http;

    private ExampleHost(
        Process process,
        HttpClient http,
        string root,
        string baseUrl,
        string packagePath,
        string databasePath,
        string backupRoot)
    {
        _process = process;
        _http = http;
        Root = root;
        BaseUrl = baseUrl;
        PackagePath = packagePath;
        DatabasePath = databasePath;
        BackupRoot = backupRoot;
        Client = new HttpSchedulerApiClient(http, AdminToken);
    }

    public string Root { get; }

    public string BaseUrl { get; }

    public string PackagePath { get; }

    public string DatabasePath { get; }

    public string BackupRoot { get; }

    public ISchedulerApiClient Client { get; }

    public static async Task<ExampleHost> StartAsync(TestPackageKey key, CancellationToken cancellationToken)
    {
        string hostAssembly = ResolveHostAssembly();
        string root = Path.Combine(Path.GetTempPath(), "jobscheduler-example-e2e", Guid.NewGuid().ToString("N"));
        string dataRoot = Path.Combine(root, "data");
        string databasePath = Path.Combine(dataRoot, "jobscheduler.db");
        string backupRoot = Path.Combine(dataRoot, "backups");
        string packagePath = Path.Combine(root, "example-package.zip");
        Directory.CreateDirectory(root);
        File.WriteAllBytes(packagePath, ExamplePluginPackage.CreateSigned(key));

        int port = GetFreePort();
        string baseUrl = $"http://localhost:{port.ToString(CultureInfo.InvariantCulture)}";

        ProcessStartInfo startInfo = new("dotnet")
        {
            WorkingDirectory = Path.GetDirectoryName(hostAssembly)!,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        startInfo.ArgumentList.Add(hostAssembly);
        startInfo.Environment["AllowedHosts"] = "*";
        startInfo.Environment["ASPNETCORE_ENVIRONMENT"] = "Production";
        startInfo.Environment["JobScheduler__DataRoot"] = dataRoot;
        startInfo.Environment["JobScheduler__DatabasePath"] = databasePath;
        startInfo.Environment["JobScheduler__ArtifactsRoot"] = Path.Combine(dataRoot, "artifacts");
        startInfo.Environment["JobScheduler__StagingRoot"] = Path.Combine(dataRoot, "staging");
        startInfo.Environment["JobScheduler__BackupRoot"] = backupRoot;
        startInfo.Environment["JobScheduler__LogsRoot"] = Path.Combine(root, "logs");
        startInfo.Environment["JobScheduler__PackagePublicKeyPath"] = key.PublicKeyPath;
        startInfo.Environment["JobScheduler__SecretStore__StoreRoot"] = Path.Combine(dataRoot, "secrets");
        startInfo.Environment["JobScheduler__SecretStore__KeyPath"] = Path.Combine(root, "keys", "secret-store.key");
        startInfo.Environment["JobScheduler__SchedulerName"] = "example-" + Guid.NewGuid().ToString("N");
        startInfo.Environment["JobScheduler__ManagementApi__Enabled"] = "true";
        startInfo.Environment["JobScheduler__ManagementApi__AllowRemoteAccess"] = "false";
        startInfo.Environment["JobScheduler__ManagementApi__Port"] = port.ToString(CultureInfo.InvariantCulture);
        startInfo.Environment["JobScheduler__ManagementApi__Credentials__0__Scopes__6"] = "read";
        startInfo.Environment["SCHEDULER_BOOTSTRAP_MANAGEMENT_TOKEN"] = AdminToken;

        Process process = new() { StartInfo = startInfo };
        ExampleHost host = new(
            process,
            http: new HttpClient { BaseAddress = new Uri(baseUrl), Timeout = TimeSpan.FromSeconds(60) },
            root,
            baseUrl,
            packagePath,
            databasePath,
            backupRoot);
        process.OutputDataReceived += (_, args) => host.AppendOutput(args.Data);
        process.ErrorDataReceived += (_, args) => host.AppendOutput(args.Data);

        process.Start();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        await host.WaitUntilReadyAsync(cancellationToken);
        return host;
    }

    /// <summary>Creates an independent client; pass <c>null</c> for an unauthenticated client.</summary>
    public HttpClient CreateHttpClient(string? token)
    {
        HttpClient http = new() { BaseAddress = new Uri(BaseUrl), Timeout = TimeSpan.FromSeconds(60) };
        if (!string.IsNullOrEmpty(token))
        {
            http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }

        return http;
    }

    public ISchedulerApiClient CreateApiClient(string? token) => new HttpSchedulerApiClient(CreateHttpClient(token), token);

    /// <summary>Reads the accumulated structured host log files, for assertions.</summary>
    public string ReadHostLog()
    {
        string logsRoot = Path.Combine(Root, "logs");
        if (!Directory.Exists(logsRoot))
        {
            return string.Empty;
        }

        StringBuilder log = new();
        foreach (string file in Directory.EnumerateFiles(logsRoot, "host-*.log"))
        {
            using FileStream stream = new(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using StreamReader reader = new(stream);
            log.AppendLine(reader.ReadToEnd());
        }

        return log.ToString();
    }

    public async ValueTask DisposeAsync()
    {
        _http.Dispose();

        try
        {
            if (!_process.HasExited)
            {
                _process.Kill(entireProcessTree: true);
            }

            await _process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(15));
        }
        catch (Exception exception) when (exception is InvalidOperationException or TimeoutException)
        {
        }

        _process.Dispose();
        SqliteConnection.ClearAllPools();

        try
        {
            Directory.Delete(Root, recursive: true);
        }
        catch (DirectoryNotFoundException)
        {
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private async Task WaitUntilReadyAsync(CancellationToken cancellationToken)
    {
        using HttpClient probe = new() { BaseAddress = new Uri(BaseUrl), Timeout = TimeSpan.FromSeconds(3) };
        Exception? lastError = null;

        for (int attempt = 0; attempt < 240; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (_process.HasExited)
            {
                throw new InvalidOperationException(
                    $"The example host exited with code {_process.ExitCode} during startup.\n{Output()}");
            }

            try
            {
                using HttpResponseMessage response = await probe.GetAsync("healthz", cancellationToken);
                if (response.IsSuccessStatusCode)
                {
                    return;
                }
            }
            catch (HttpRequestException exception)
            {
                lastError = exception;
            }
            catch (TaskCanceledException exception)
            {
                lastError = exception;
            }

            await Task.Delay(250, cancellationToken);
        }

        throw new TimeoutException($"The example host did not become ready. Last error: {lastError?.Message}\n{Output()}");
    }

    private void AppendOutput(string? line)
    {
        if (line is null)
        {
            return;
        }

        lock (_outputLock)
        {
            _output.AppendLine(line);
        }
    }

    private string Output()
    {
        lock (_outputLock)
        {
            return _output.ToString();
        }
    }

    private static int GetFreePort()
    {
        TcpListener listener = new(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private static string ResolveHostAssembly()
    {
        DirectoryInfo testsOutput = new(AppContext.BaseDirectory);
        string configuration = testsOutput.Parent!.Name;
        string targetFramework = testsOutput.Name;
        DirectoryInfo? projectDirectory = testsOutput.Parent!.Parent!.Parent;
        DirectoryInfo? sourceDirectory = projectDirectory!.Parent;

        string hostAssembly = Path.Combine(
            sourceDirectory!.FullName,
            "Scheduler.Host",
            "bin",
            configuration,
            targetFramework,
            "Scheduler.Host.dll");

        if (!File.Exists(hostAssembly))
        {
            throw new FileNotFoundException(
                $"The Scheduler.Host build output was not found at '{hostAssembly}'. Build the solution before running the end-to-end tests.",
                hostAssembly);
        }

        return hostAssembly;
    }
}

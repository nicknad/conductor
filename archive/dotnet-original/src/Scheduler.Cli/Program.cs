using Scheduler.Cli;

string baseUrl = Environment.GetEnvironmentVariable("SCHEDULER_API_URL") ?? "http://localhost:5000";
string? token = Environment.GetEnvironmentVariable("SCHEDULER_API_TOKEN");
string[] commandArgs = StripOptions(args, ref baseUrl, ref token);

using HttpClient http = new()
{
    BaseAddress = new Uri(baseUrl, UriKind.Absolute),
    Timeout = TimeSpan.FromSeconds(30),
};

return await SchedulerCli.RunAsync(
    commandArgs,
    new HttpSchedulerApiClient(http, token),
    Console.In,
    Console.Out,
    Console.Error,
    CancellationToken.None);

static string[] StripOptions(string[] args, ref string baseUrl, ref string? token)
{
    List<string> remaining = [];
    for (int index = 0; index < args.Length; index++)
    {
        if (args[index] == "--api" && index + 1 < args.Length)
        {
            baseUrl = args[++index];
            continue;
        }

        if (args[index] == "--token" && index + 1 < args.Length)
        {
            token = args[++index];
            continue;
        }

        remaining.Add(args[index]);
    }

    return [.. remaining];
}

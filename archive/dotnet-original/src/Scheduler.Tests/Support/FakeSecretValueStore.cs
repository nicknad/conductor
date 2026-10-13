using Scheduler.Application.Secrets;

namespace Scheduler.Tests.Support;

/// <summary>An in-memory <see cref="ISecretValueStore" /> for deterministic tests; never holds a real secret.</summary>
internal sealed class FakeSecretValueStore : ISecretValueStore
{
    private readonly Dictionary<string, string> _values = new(StringComparer.Ordinal);

    public Task<string?> GetAsync(string secretReference, CancellationToken cancellationToken = default) =>
        Task.FromResult(_values.TryGetValue(secretReference, out string? value) ? value : null);

    public Task SetAsync(string secretReference, string value, CancellationToken cancellationToken = default)
    {
        _values[secretReference] = value;
        return Task.CompletedTask;
    }

    public Task RemoveAsync(string secretReference, CancellationToken cancellationToken = default)
    {
        _values.Remove(secretReference);
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<string>> ListReferencesAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<string>>(_values.Keys.OrderBy(key => key, StringComparer.Ordinal).ToList());
}

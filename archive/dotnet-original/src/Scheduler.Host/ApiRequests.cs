namespace Scheduler.Host;

/// <summary>Body of a secret set/rotate request. The value is written to the encrypted store and never echoed.</summary>
public sealed record SecretWrite(string Reference, string Value);

/// <summary>Body of a secret grant request.</summary>
public sealed record SecretGrantRequest(string PluginId, string? JobId, string SecretReference);

/// <summary>Body of a backup request; the destination is a server-side path.</summary>
public sealed record BackupRequest(string Destination);

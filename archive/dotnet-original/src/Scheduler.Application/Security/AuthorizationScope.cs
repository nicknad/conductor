namespace Scheduler.Application.Security;

/// <summary>
/// A management-API permission. Each action is a separate scope so a credential
/// can be granted the least privilege it needs.
/// </summary>
[Flags]
public enum AuthorizationScope
{
    None = 0,
    Read = 1 << 0,
    Install = 1 << 1,
    Validate = 1 << 2,
    Activate = 1 << 3,
    Deactivate = 1 << 4,
    Rollback = 1 << 5,
    Remove = 1 << 6,
    ManualRun = 1 << 7,
    SecretAdmin = 1 << 8,

    /// <summary>Every scope; used only when authentication is explicitly disabled.</summary>
    All = Read | Install | Validate | Activate | Deactivate | Rollback | Remove | ManualRun | SecretAdmin,
}

/// <summary>Parses scope names as they appear in management-API configuration.</summary>
public static class AuthorizationScopeNames
{
    /// <summary>
    /// Parses a configured scope name. Names are matched case-insensitively and may use
    /// kebab-case (for example <c>manual-run</c>, <c>secret-admin</c>).
    /// </summary>
    public static bool TryParse(string? name, out AuthorizationScope scope)
    {
        scope = AuthorizationScope.None;
        if (string.IsNullOrWhiteSpace(name))
        {
            return false;
        }

        return Enum.TryParse(name.Replace("-", string.Empty, StringComparison.Ordinal), ignoreCase: true, out scope);
    }
}

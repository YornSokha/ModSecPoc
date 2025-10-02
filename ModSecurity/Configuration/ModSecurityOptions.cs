namespace ModSecPoc.ModSecurity.Configuration;

/// <summary>
/// Configuration options for ModSecurity
/// </summary>
public class ModSecurityOptions
{
    public const string SectionName = "ModSecurity";

    /// <summary>
    /// Enable or disable ModSecurity processing
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Path to the ModSecurity rules file
    /// </summary>
    public string? RulesFile { get; set; } = null;
    // public string RulesFile { get; set; } = "/etc/modsecurity/modsecurity.conf";

    /// <summary>
    /// Additional rules files to load
    /// </summary>
    public List<string> AdditionalRulesFiles { get; set; } = new();

    /// <summary>
    /// Log level for ModSecurity
    /// </summary>
    public ModSecurityLogLevel LogLevel { get; set; } = ModSecurityLogLevel.Info;

    /// <summary>
    /// Whether to block requests that trigger rules (enforce) or just log them (detect)
    /// </summary>
    public bool EnforceMode { get; set; } = false;

    /// <summary>
    /// Custom response status code when blocking requests
    /// </summary>
    public int BlockStatusCode { get; set; } = 403;

    /// <summary>
    /// Custom response message when blocking requests
    /// </summary>
    public string BlockMessage { get; set; } = "Access Denied";

    /// <summary>
    /// Maximum request body size to inspect (in bytes)
    /// </summary>
    public int MaxRequestBodySize { get; set; } = 1024 * 1024; // 1MB

    /// <summary>
    /// Maximum response body size to inspect (in bytes)
    /// </summary>
    public int MaxResponseBodySize { get; set; } = 1024 * 1024; // 1MB
}

/// <summary>
/// ModSecurity log levels
/// </summary>
public enum ModSecurityLogLevel
{
    Emergency = 0,
    Alert = 1,
    Critical = 2,
    Error = 3,
    Warning = 4,
    Notice = 5,
    Info = 6,
    Debug = 7
}
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
    /// Directory containing OWASP CRS (or other) rule .conf files. Defaults to ./modsecurity/rules
    /// </summary>
    public string? RulesDirectory { get; set; }

    /// <summary>
    /// Automatically scan and load OWASP CRS rule .conf files from <see cref="RulesDirectory"/>.
    /// Loaded after the primary RulesFile and crs-setup.conf. Set false to disable implicit CRS loading.
    /// </summary>
    public bool AutoLoadCrs { get; set; } = true;

    /// <summary>
    /// Override paranoia level (sets both detection and blocking if >0). 0 = do not override.
    /// </summary>
    public int ParanoiaLevel { get; set; } = 0;

    /// <summary>
    /// When true, injects a SecAction to set tx.crs_setup_version if the provided crs-setup.conf does not set it (prevents rule 901001 warning).
    /// </summary>
    public bool EnsureCrsSetupVersion { get; set; } = true;

    /// <summary>
    /// Optional override of anomaly score thresholds. Null means leave as defined by crs-setup.conf.
    /// </summary>
    public int? InboundAnomalyScoreThreshold { get; set; }
    public int? OutboundAnomalyScoreThreshold { get; set; }
    public int? TotalAnomalyScoreThreshold { get; set; }

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

    /// <summary>
    /// When true, after collecting candidate CRS rule files, order them by the smallest rule ID contained in each file (ascending),
    /// instead of the default semantic grouping (REQUEST-*, RESPONSE-*). This is generally NOT recommended because CRS relies on
    /// its documented load order for skipAfter, initialization and variable setup semantics. Use only for experimental analysis.
    /// </summary>
    public bool LoadRulesByMinIdOrder { get; set; } = false;
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
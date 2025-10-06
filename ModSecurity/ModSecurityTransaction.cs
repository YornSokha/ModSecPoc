using ModSecPoc.ModSecurity.Native;
using System.Runtime.InteropServices;
using System.Text;

namespace ModSecPoc.ModSecurity;

/// <summary>
/// Wrapper for ModSecurity transaction
/// </summary>
public class ModSecurityTransaction : IDisposable
{
    private IntPtr _transactionHandle;
    private bool _disposed = false;
    private readonly LogCallback? _logCallback;
    private readonly List<string> _logLines = new();

    public ModSecurityTransaction(IntPtr modsecHandle, ModSecurityRuleSet ruleSet)
    {
        // Create log callback - this is essential for proper ModSecurity operation
        _logCallback = LogCallbackHandler;
        var logCallbackPtr = _logCallback != null ? Marshal.GetFunctionPointerForDelegate(_logCallback) : IntPtr.Zero;

        _transactionHandle = ModSecurityNative.msc_new_transaction(modsecHandle, ruleSet.Handle, logCallbackPtr);
        if (_transactionHandle == IntPtr.Zero)
        {
            throw new InvalidOperationException("Failed to create ModSecurity transaction");
        }
        
        // Keep the callback alive for the lifetime of this transaction
        GC.KeepAlive(_logCallback);
    }

    private void LogCallbackHandler(IntPtr data, IntPtr logData)
    {
        if (logData != IntPtr.Zero)
        {
            try
            {
                var line = Marshal.PtrToStringAnsi(logData);
                if (!string.IsNullOrWhiteSpace(line))
                {
                    lock (_logLines)
                    {
                        if (_logLines.Count < 500) // simple cap to avoid unbounded growth
                        {
                            _logLines.Add(line);
                        }
                    }
                    
                    // Debug output to see what ModSecurity is logging
                    System.Diagnostics.Debug.WriteLine($"ModSecurity Log: {line}");
                    
                    // Also write to console for immediate visibility
                    Console.WriteLine($"[ModSec] {line}");
                }
            }
            catch (Exception ex)
            {
                // Log callback errors for debugging
                System.Diagnostics.Debug.WriteLine($"LogCallback error: {ex.Message}");
            }
        }
    }

    /// <summary>
    /// Get collected native log lines for this transaction.
    /// </summary>
    public IReadOnlyList<string> GetLogLines()
    {
        lock (_logLines)
        {
            return _logLines.ToList();
        }
    }

    /// <summary>
    /// Process connection information
    /// </summary>
    public int ProcessConnection(string clientIp, int clientPort, string serverIp, int serverPort)
    {
        var clientPtr = Marshal.StringToHGlobalAnsi(clientIp);
        var serverPtr = Marshal.StringToHGlobalAnsi(serverIp);

        try
        {
            return ModSecurityNative.msc_process_connection(_transactionHandle, clientPtr, clientPort, serverPtr, serverPort);
        }
        finally
        {
            Marshal.FreeHGlobal(clientPtr);
            Marshal.FreeHGlobal(serverPtr);
        }
    }

    /// <summary>
    /// Process URI information
    /// </summary>
    public int ProcessUri(string uri, string method, string httpVersion)
    {
        var uriPtr = Marshal.StringToHGlobalAnsi(uri);
        var methodPtr = Marshal.StringToHGlobalAnsi(method);
        var versionPtr = Marshal.StringToHGlobalAnsi(httpVersion);

        try
        {
            return ModSecurityNative.msc_process_uri(_transactionHandle, uriPtr, methodPtr, versionPtr);
        }
        finally
        {
            Marshal.FreeHGlobal(uriPtr);
            Marshal.FreeHGlobal(methodPtr);
            Marshal.FreeHGlobal(versionPtr);
        }
    }

    /// <summary>
    /// Add request header
    /// </summary>
    public int AddRequestHeader(string name, string value)
    {
        var namePtr = Marshal.StringToHGlobalAnsi(name);
        var valuePtr = Marshal.StringToHGlobalAnsi(value);

        try
        {
            return ModSecurityNative.msc_add_request_header(_transactionHandle, namePtr, valuePtr);
        }
        finally
        {
            Marshal.FreeHGlobal(namePtr);
            Marshal.FreeHGlobal(valuePtr);
        }
    }

    /// <summary>
    /// Add response header
    /// </summary>
    public int AddResponseHeader(string name, string value)
    {
        var namePtr = Marshal.StringToHGlobalAnsi(name);
        var valuePtr = Marshal.StringToHGlobalAnsi(value);

        try
        {
            return ModSecurityNative.msc_add_response_header(_transactionHandle, namePtr, valuePtr);
        }
        finally
        {
            Marshal.FreeHGlobal(namePtr);
            Marshal.FreeHGlobal(valuePtr);
        }
    }

    /// <summary>
    /// Process request headers
    /// </summary>
    public int ProcessRequestHeaders()
    {
        return ModSecurityNative.msc_process_request_headers(_transactionHandle);
    }

    /// <summary>
    /// Process request body
    /// </summary>
    public int ProcessRequestBody()
    {
        return ModSecurityNative.msc_process_request_body(_transactionHandle);
    }

    /// <summary>
    /// Append request body data
    /// </summary>
    public int AppendRequestBody(byte[] body)
    {
        var bodyPtr = Marshal.AllocHGlobal(body.Length);
        try
        {
            Marshal.Copy(body, 0, bodyPtr, body.Length);
            return ModSecurityNative.msc_append_request_body(_transactionHandle, bodyPtr, body.Length);
        }
        finally
        {
            Marshal.FreeHGlobal(bodyPtr);
        }
    }

    /// <summary>
    /// Process response headers
    /// </summary>
    public int ProcessResponseHeaders(int statusCode, string protocol)
    {
        var protocolPtr = Marshal.StringToHGlobalAnsi(protocol);
        try
        {
            return ModSecurityNative.msc_process_response_headers(_transactionHandle, statusCode, protocolPtr);
        }
        finally
        {
            Marshal.FreeHGlobal(protocolPtr);
        }
    }

    /// <summary>
    /// Process response body
    /// </summary>
    public int ProcessResponseBody()
    {
        return ModSecurityNative.msc_process_response_body(_transactionHandle);
    }

    /// <summary>
    /// Append response body data
    /// </summary>
    public int AppendResponseBody(byte[] body)
    {
        var bodyPtr = Marshal.AllocHGlobal(body.Length);
        try
        {
            Marshal.Copy(body, 0, bodyPtr, body.Length);
            return ModSecurityNative.msc_append_response_body(_transactionHandle, bodyPtr, body.Length);
        }
        finally
        {
            Marshal.FreeHGlobal(bodyPtr);
        }
    }

    /// <summary>
    /// Get intervention information if any rules were triggered
    /// </summary>
    public ModSecurityInterventionResult? GetIntervention()
    {
        var result = ModSecurityNative.msc_intervention(_transactionHandle, out var intervention);
        
        // If the function returns 0 or there's no disruptive action, return null
        if (result == 0 || intervention.disruptive == 0)
        {
            return null;
        }

        return new ModSecurityInterventionResult
        {
            Status = intervention.status,
            Url = intervention.url != IntPtr.Zero ? Marshal.PtrToStringAnsi(intervention.url) : null,
            Log = intervention.log != IntPtr.Zero ? Marshal.PtrToStringAnsi(intervention.log) : null,
            IsDisruptive = intervention.disruptive != 0
        };
    }

    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (_transactionHandle != IntPtr.Zero)
            {
                ModSecurityNative.msc_transaction_cleanup(_transactionHandle);
                _transactionHandle = IntPtr.Zero;
            }
            _disposed = true;
        }
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    ~ModSecurityTransaction()
    {
        Dispose(false);
    }
}

/// <summary>
/// Result of ModSecurity intervention
/// </summary>
public class ModSecurityInterventionResult
{
    public int Status { get; set; }
    public string? Url { get; set; }
    public string? Log { get; set; }
    public bool IsDisruptive { get; set; }
}
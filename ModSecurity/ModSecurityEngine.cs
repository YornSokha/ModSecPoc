using ModSecPoc.ModSecurity.Native;
using System.Runtime.InteropServices;
using System.Text;

namespace ModSecPoc.ModSecurity;

/// <summary>
/// High-level wrapper for ModSecurity engine
/// </summary>
public class ModSecurityEngine : IDisposable
{
    private IntPtr _modsecHandle;
    private bool _disposed = false;
    private readonly ModSecurityLogCallback? _globalLogCallback;

    public ModSecurityEngine()
    {
        // Initialize the native library resolver
        ModSecurityLibraryResolver.Initialize();
        
        _modsecHandle = ModSecurityNative.msc_init();
        if (_modsecHandle == IntPtr.Zero)
        {
            throw new InvalidOperationException("Failed to initialize ModSecurity engine");
        }

        // Set connector info
        var connectorInfo = Marshal.StringToHGlobalAnsi(".NET Core ModSecurity Integration v1.0");
        ModSecurityNative.msc_set_connector_info(_modsecHandle, connectorInfo);
        Marshal.FreeHGlobal(connectorInfo);
    }

    public string WhoAmI()
    {
        var result = ModSecurityNative.msc_who_am_i(_modsecHandle);
        return Marshal.PtrToStringAnsi(result) ?? "Unknown";
    }

    public ModSecurityRuleSet CreateRuleSet()
    {
        return new ModSecurityRuleSet();
    }

    public ModSecurityTransaction CreateTransaction(ModSecurityRuleSet ruleSet)
    {
        return new ModSecurityTransaction(_modsecHandle, ruleSet);
    }

    public IntPtr Handle => _modsecHandle;

    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (_modsecHandle != IntPtr.Zero)
            {
                ModSecurityNative.msc_cleanup(_modsecHandle);
                _modsecHandle = IntPtr.Zero;
            }
            _disposed = true;
        }
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    ~ModSecurityEngine()
    {
        Dispose(false);
    }
}
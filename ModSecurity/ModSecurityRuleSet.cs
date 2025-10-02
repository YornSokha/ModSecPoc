using ModSecPoc.ModSecurity.Native;
using System.Runtime.InteropServices;

namespace ModSecPoc.ModSecurity;

/// <summary>
/// Wrapper for ModSecurity rule set
/// </summary>
public class ModSecurityRuleSet : IDisposable
{
    private IntPtr _rulesHandle;
    private bool _disposed = false;

    public ModSecurityRuleSet()
    {
        _rulesHandle = ModSecurityNative.msc_create_rules_set();
        if (_rulesHandle == IntPtr.Zero)
        {
            throw new InvalidOperationException("Failed to create ModSecurity rule set");
        }
    }

    /// <summary>
    /// Load rules from a file
    /// </summary>
    /// <param name="rulesFilePath">Path to the ModSecurity rules file</param>
    /// <returns>True if rules loaded successfully, false otherwise</returns>
    public bool LoadRulesFromFile(string rulesFilePath)
    {
        if (!File.Exists(rulesFilePath))
        {
            throw new FileNotFoundException($"Rules file not found: {rulesFilePath}");
        }

        var filePathPtr = Marshal.StringToHGlobalAnsi(rulesFilePath);
        var errorPtr = IntPtr.Zero;

        try
        {
            var result = ModSecurityNative.msc_rules_add_file(_rulesHandle, filePathPtr, ref errorPtr);
            
            if (result != 0 && errorPtr != IntPtr.Zero)
            {
                var errorMessage = Marshal.PtrToStringAnsi(errorPtr);
                throw new InvalidOperationException($"Failed to load rules: {errorMessage}");
            }

            return result == 0;
        }
        finally
        {
            Marshal.FreeHGlobal(filePathPtr);
            if (errorPtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(errorPtr);
            }
        }
    }

    public IntPtr Handle => _rulesHandle;

    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (_rulesHandle != IntPtr.Zero)
            {
                ModSecurityNative.msc_rules_cleanup(_rulesHandle);
                _rulesHandle = IntPtr.Zero;
            }
            _disposed = true;
        }
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    ~ModSecurityRuleSet()
    {
        Dispose(false);
    }
}
using System.Runtime.InteropServices;

namespace ModSecPoc.ModSecurity.Native;

/// <summary>
/// Native P/Invoke declarations for ModSecurity native library
/// Uses libmodsecurity.so on Linux/macOS and modsecurity.dll on Windows
/// </summary>
public static class ModSecurityNative
{
    private const string LibModSecurity = "libmodsecurity";

    #region ModSecurity Engine Functions
    
    [DllImport(LibModSecurity, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr msc_init();

    [DllImport(LibModSecurity, CallingConvention = CallingConvention.Cdecl)]
    public static extern void msc_cleanup(IntPtr modsec);

    [DllImport(LibModSecurity, CallingConvention = CallingConvention.Cdecl)]
    public static extern int msc_rules_add_file(IntPtr rules, IntPtr file, ref IntPtr error);

    [DllImport(LibModSecurity, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr msc_create_rules_set();

    [DllImport(LibModSecurity, CallingConvention = CallingConvention.Cdecl)]
    public static extern void msc_rules_cleanup(IntPtr rules);

    #endregion

    #region Transaction Functions

    [DllImport(LibModSecurity, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr msc_new_transaction(IntPtr modsec, IntPtr rules, IntPtr logCb);

    [DllImport(LibModSecurity, CallingConvention = CallingConvention.Cdecl)]
    public static extern void msc_transaction_cleanup(IntPtr transaction);

    [DllImport(LibModSecurity, CallingConvention = CallingConvention.Cdecl)]
    public static extern int msc_process_connection(IntPtr transaction, IntPtr client, int cPort, IntPtr server, int sPort);

    [DllImport(LibModSecurity, CallingConvention = CallingConvention.Cdecl)]
    public static extern int msc_process_uri(IntPtr transaction, IntPtr uri, IntPtr protocol, IntPtr httpVersion);

    [DllImport(LibModSecurity, CallingConvention = CallingConvention.Cdecl)]
    public static extern int msc_process_request_headers(IntPtr transaction);

    [DllImport(LibModSecurity, CallingConvention = CallingConvention.Cdecl)]
    public static extern int msc_process_request_body(IntPtr transaction);

    [DllImport(LibModSecurity, CallingConvention = CallingConvention.Cdecl)]
    public static extern int msc_process_response_headers(IntPtr transaction, int code, IntPtr protocol);

    [DllImport(LibModSecurity, CallingConvention = CallingConvention.Cdecl)]
    public static extern int msc_process_response_body(IntPtr transaction);

    [DllImport(LibModSecurity, CallingConvention = CallingConvention.Cdecl)]
    public static extern int msc_add_request_header(IntPtr transaction, IntPtr key, IntPtr value);

    [DllImport(LibModSecurity, CallingConvention = CallingConvention.Cdecl)]
    public static extern int msc_add_response_header(IntPtr transaction, IntPtr key, IntPtr value);

    [DllImport(LibModSecurity, CallingConvention = CallingConvention.Cdecl)]
    public static extern int msc_append_request_body(IntPtr transaction, IntPtr body, int size);

    [DllImport(LibModSecurity, CallingConvention = CallingConvention.Cdecl)]
    public static extern int msc_append_response_body(IntPtr transaction, IntPtr body, int size);

    #endregion

    #region Intervention Functions

    [DllImport(LibModSecurity, CallingConvention = CallingConvention.Cdecl)]
    public static extern int msc_intervention(IntPtr transaction, out ModSecurityIntervention intervention);

    [DllImport(LibModSecurity, CallingConvention = CallingConvention.Cdecl)]
    public static extern void msc_intervention_cleanup(IntPtr intervention);

    #endregion

    #region Utility Functions

    [DllImport(LibModSecurity, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr msc_who_am_i(IntPtr modsec);

    [DllImport(LibModSecurity, CallingConvention = CallingConvention.Cdecl)]
    public static extern void msc_set_connector_info(IntPtr modsec, IntPtr connector);

    // Note: msc_set_log_cb might not be available in all ModSecurity versions
    // [DllImport(LibModSecurity, CallingConvention = CallingConvention.Cdecl)]
    // public static extern void msc_set_log_cb(IntPtr modsec, IntPtr logCb);

    #endregion
}

/// <summary>
/// ModSecurity intervention structure
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct ModSecurityIntervention
{
    public int status;
    public IntPtr url;
    public IntPtr log;
    public int disruptive;
}

/// <summary>
/// Callback delegate for ModSecurity logging
/// </summary>
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate void LogCallback(IntPtr data, IntPtr logData);

/// <summary>
/// Alternative log callback signature that matches libmodsecurity exactly
/// </summary>
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate void ModSecurityLogCallback(IntPtr data, IntPtr logData);
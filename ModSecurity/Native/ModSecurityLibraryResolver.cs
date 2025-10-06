using System.Reflection;
using System.Runtime.InteropServices;

namespace ModSecPoc.ModSecurity.Native;

/// <summary>
/// Native library resolver for ModSecurity
/// Handles loading libmodsecurity from various possible locations
/// </summary>
public static class ModSecurityLibraryResolver
{
    private static bool _isInitialized = false;

    /// <summary>
    /// Initialize the library resolver
    /// This should be called once before using ModSecurity functions
    /// </summary>
    public static void Initialize()
    {
        if (_isInitialized) return;

        NativeLibrary.SetDllImportResolver(typeof(ModSecurityNative).Assembly, DllImportResolver);
        _isInitialized = true;
    }

    private static IntPtr DllImportResolver(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (libraryName == "libmodsecurity")
        {

            if (NativeLibrary.TryLoad("./ModSecurity/Native/libmodsecurity.so", out var handle))
            {
                Console.WriteLine($"Successfully loaded ModSecurity library");
                return handle;
            }

            // If we couldn't find the library, provide helpful error information
            Console.WriteLine("Failed to load ModSecurity library. Tried the following locations:");
        
        }

        return IntPtr.Zero;
    }
}
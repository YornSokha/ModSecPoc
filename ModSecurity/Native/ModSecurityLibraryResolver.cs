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
            // Determine the appropriate library file based on the operating system
            string libraryPath = GetNativeLibraryPath();
            
            if (NativeLibrary.TryLoad(libraryPath, out var handle))
            {
                Console.WriteLine($"Successfully loaded ModSecurity library from: {libraryPath}");
                return handle;
            }

            // If we couldn't find the library, provide helpful error information
            Console.WriteLine($"Failed to load ModSecurity library from: {libraryPath}");
            Console.WriteLine("Make sure the appropriate native library is present in the ModSecurity/Native directory.");
        }

        return IntPtr.Zero;
    }

    /// <summary>
    /// Get the appropriate native library path based on the current operating system
    /// </summary>
    /// <returns>The path to the native library file</returns>
    private static string GetNativeLibraryPath()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return "./ModSecurity/Native/modsecurity.dll";
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            return "./ModSecurity/Native/libmodsecurity.so";
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            return "./ModSecurity/Native/libmodsecurity.dylib";
        }
        else
        {
            // Default to .so for unknown platforms
            return "./ModSecurity/Native/libmodsecurity.so";
        }
    }
}
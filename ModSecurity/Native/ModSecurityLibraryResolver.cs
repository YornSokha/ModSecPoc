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
            // Try different possible library names and paths
            var possibleNames = new[]
            {
                // "libmodsecurity.so.3",      // Versioned library
                "libmodsecuritye.so",        // Symbolic link
                // "libmodsecurity",           // Without extension
                // "/usr/local/modsecurity/lib/libmodsecurity.so",  // Full path
                // "/usr/lib/x86_64-linux-gnu/libmodsecurity.so",   // Standard Ubuntu path
                // "/usr/lib/libmodsecurity.so",                    // Standard path
                // "/opt/modsecurity/lib/libmodsecurity.so"         // Alternative installation path
            };

            foreach (var name in possibleNames)
            {
                if (NativeLibrary.TryLoad(name, out var handle))
                {
                    Console.WriteLine($"Successfully loaded ModSecurity library: {name}");
                    return handle;
                }
            }

            // If we couldn't find the library, provide helpful error information
            Console.WriteLine("Failed to load ModSecurity library. Tried the following locations:");
            foreach (var name in possibleNames)
            {
                Console.WriteLine($"  - {name}");
            }
            Console.WriteLine("\nPlease ensure ModSecurity is installed. On Ubuntu/Debian:");
            Console.WriteLine("  sudo apt-get install libmodsecurity3 libmodsecurity-dev");
            Console.WriteLine("\nOr build from source:");
            Console.WriteLine("  https://github.com/SpiderLabs/ModSecurity");
        }

        return IntPtr.Zero;
    }
}
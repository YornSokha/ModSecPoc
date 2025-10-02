using Microsoft.AspNetCore.Mvc;
using System.Text.Json;

namespace ModSecPoc.Controllers;

[ApiController]
[Route("api/[controller]")]
public class ModSecurityTestController : ControllerBase
{
    private readonly ILogger<ModSecurityTestController> _logger;

    public ModSecurityTestController(ILogger<ModSecurityTestController> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Run comprehensive ModSecurity test suite
    /// </summary>
    [HttpGet("suite")]
    public async Task<IActionResult> RunTestSuite()
    {
        var results = new List<TestResult>();
        var httpClient = new HttpClient();
        var baseUrl = $"{Request.Scheme}://{Request.Host}";

        try
        {
            // Test 1: Normal request (should pass)
            results.Add(await RunTest(httpClient, baseUrl, new TestCase
            {
                Name = "Normal Request",
                Description = "Basic request that should pass through ModSecurity",
                Method = "GET",
                Endpoint = "/test/modsecurity",
                ExpectedStatus = 200,
                ShouldBlock = false
            }));

            // Test 2: SQL Injection in POST body
            results.Add(await RunTest(httpClient, baseUrl, new TestCase
            {
                Name = "SQL Injection - POST Body",
                Description = "SQL injection attempt in POST request body",
                Method = "POST",
                Endpoint = "/test/sqli",
                Body = JsonSerializer.Serialize(new { data = "1 OR 1=1 UNION SELECT * FROM users" }),
                ContentType = "application/json",
                ExpectedStatus = 403,
                ShouldBlock = true
            }));

            // Test 3: XSS in POST body
            results.Add(await RunTest(httpClient, baseUrl, new TestCase
            {
                Name = "XSS Attack - POST Body",
                Description = "XSS attempt in POST request body",
                Method = "POST",
                Endpoint = "/test/xss",
                Body = JsonSerializer.Serialize(new { data = "<script>alert('XSS')</script>" }),
                ContentType = "application/json",
                ExpectedStatus = 403,
                ShouldBlock = true
            }));

            // Test 4: Directory Traversal in URL parameter
            results.Add(await RunTest(httpClient, baseUrl, new TestCase
            {
                Name = "Directory Traversal - URL Parameter",
                Description = "Directory traversal attempt in URL parameter",
                Method = "GET",
                Endpoint = "/test/traversal?path=../../../etc/passwd",
                ExpectedStatus = 403,
                ShouldBlock = true
            }));

            // Test 5: SQL Injection in URL parameter
            results.Add(await RunTest(httpClient, baseUrl, new TestCase
            {
                Name = "SQL Injection - URL Parameter",
                Description = "SQL injection attempt in URL parameter",
                Method = "GET",
                Endpoint = "/test/traversal?path=' OR '1'='1",
                ExpectedStatus = 403,
                ShouldBlock = true
            }));

            // Test 6: Suspicious User-Agent
            results.Add(await RunTest(httpClient, baseUrl, new TestCase
            {
                Name = "Suspicious User-Agent",
                Description = "Request with suspicious User-Agent header",
                Method = "GET",
                Endpoint = "/test/modsecurity",
                Headers = new Dictionary<string, string> { { "User-Agent", "sqlmap/1.0" } },
                ExpectedStatus = 403,
                ShouldBlock = true
            }));

            // Test 7: Multiple attack vectors
            results.Add(await RunTest(httpClient, baseUrl, new TestCase
            {
                Name = "Multiple Attack Vectors",
                Description = "Request with multiple attack patterns",
                Method = "POST",
                Endpoint = "/test/sqli?param=<script>alert(1)</script>",
                Body = JsonSerializer.Serialize(new { data = "'; DROP TABLE users; --", xss = "<img src=x onerror=alert(1)>" }),
                ContentType = "application/json",
                ExpectedStatus = 403,
                ShouldBlock = true
            }));

            // Test 8: Large payload test
            results.Add(await RunTest(httpClient, baseUrl, new TestCase
            {
                Name = "Large Payload",
                Description = "Test with large request body",
                Method = "POST",
                Endpoint = "/test/sqli",
                Body = JsonSerializer.Serialize(new { data = new string('A', 1000) }),
                ContentType = "application/json",
                ExpectedStatus = 200,
                ShouldBlock = false
            }));

            // Test 9: Weather forecast endpoint (should pass)
            results.Add(await RunTest(httpClient, baseUrl, new TestCase
            {
                Name = "Weather Forecast - Normal",
                Description = "Normal application endpoint should work",
                Method = "GET",
                Endpoint = "/weatherforecast",
                ExpectedStatus = 200,
                ShouldBlock = false
            }));

            var summary = new TestSuiteSummary
            {
                TotalTests = results.Count,
                PassedTests = results.Count(r => r.Passed),
                FailedTests = results.Count(r => !r.Passed),
                ExecutionTime = results.Sum(r => r.ExecutionTimeMs),
                Results = results
            };

            return Ok(summary);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error running test suite");
            return StatusCode(500, new { error = "Failed to run test suite", message = ex.Message });
        }
        finally
        {
            httpClient.Dispose();
        }
    }

    /// <summary>
    /// Run a specific test case
    /// </summary>
    [HttpPost("run")]
    public async Task<IActionResult> RunSpecificTest([FromBody] TestCase testCase)
    {
        var httpClient = new HttpClient();
        var baseUrl = $"{Request.Scheme}://{Request.Host}";

        try
        {
            var result = await RunTest(httpClient, baseUrl, testCase);
            return Ok(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error running specific test: {TestName}", testCase.Name);
            return StatusCode(500, new { error = "Failed to run test", message = ex.Message });
        }
        finally
        {
            httpClient.Dispose();
        }
    }

    /// <summary>
    /// Get available test templates
    /// </summary>
    [HttpGet("templates")]
    public IActionResult GetTestTemplates()
    {
        var templates = new[]
        {
            new TestCase
            {
                Name = "SQL Injection Template",
                Description = "Template for SQL injection testing",
                Method = "POST",
                Endpoint = "/test/sqli",
                Body = "{ \"data\": \"YOUR_SQL_INJECTION_HERE\" }",
                ContentType = "application/json",
                ExpectedStatus = 403,
                ShouldBlock = true
            },
            new TestCase
            {
                Name = "XSS Template",
                Description = "Template for XSS testing",
                Method = "POST",
                Endpoint = "/test/xss",
                Body = "{ \"data\": \"YOUR_XSS_PAYLOAD_HERE\" }",
                ContentType = "application/json",
                ExpectedStatus = 403,
                ShouldBlock = true
            },
            new TestCase
            {
                Name = "Directory Traversal Template",
                Description = "Template for directory traversal testing",
                Method = "GET",
                Endpoint = "/test/traversal?path=YOUR_TRAVERSAL_PATH_HERE",
                ExpectedStatus = 403,
                ShouldBlock = true
            }
        };

        return Ok(templates);
    }

    private async Task<TestResult> RunTest(HttpClient httpClient, string baseUrl, TestCase testCase)
    {
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        var result = new TestResult
        {
            TestName = testCase.Name,
            Description = testCase.Description,
            ExpectedStatus = testCase.ExpectedStatus,
            ShouldBlock = testCase.ShouldBlock
        };

        try
        {
            var requestUri = $"{baseUrl}{testCase.Endpoint}";
            var request = new HttpRequestMessage(new HttpMethod(testCase.Method), requestUri);

            // Add headers
            if (testCase.Headers != null)
            {
                foreach (var header in testCase.Headers)
                {
                    request.Headers.Add(header.Key, header.Value);
                }
            }

            // Add body for POST/PUT requests
            if (!string.IsNullOrEmpty(testCase.Body))
            {
                request.Content = new StringContent(testCase.Body, System.Text.Encoding.UTF8, testCase.ContentType ?? "application/json");
            }

            var response = await httpClient.SendAsync(request);
            stopwatch.Stop();

            result.ActualStatus = (int)response.StatusCode;
            result.ResponseContent = await response.Content.ReadAsStringAsync();
            result.ExecutionTimeMs = (int)stopwatch.ElapsedMilliseconds;

            // Determine if test passed
            if (testCase.ShouldBlock)
            {
                // Should be blocked - expect 4xx or 5xx status
                result.Passed = result.ActualStatus >= 400;
                result.Message = result.Passed ? "Request correctly blocked" : $"Request should have been blocked but got {result.ActualStatus}";
            }
            else
            {
                // Should pass through - expect 2xx status
                result.Passed = result.ActualStatus >= 200 && result.ActualStatus < 300;
                result.Message = result.Passed ? "Request correctly allowed" : $"Request should have been allowed but got {result.ActualStatus}";
            }

            // Additional validation for expected status
            if (testCase.ExpectedStatus > 0)
            {
                var statusMatches = result.ActualStatus == testCase.ExpectedStatus;
                if (!statusMatches)
                {
                    result.Message += $" (Expected {testCase.ExpectedStatus}, got {result.ActualStatus})";
                    result.Passed = false;
                }
            }
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            result.ExecutionTimeMs = (int)stopwatch.ElapsedMilliseconds;
            result.Passed = false;
            result.Message = $"Test failed with exception: {ex.Message}";
            result.ActualStatus = 0;
        }

        return result;
    }
}

public class TestCase
{
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Method { get; set; } = "GET";
    public string Endpoint { get; set; } = string.Empty;
    public string? Body { get; set; }
    public string? ContentType { get; set; }
    public Dictionary<string, string>? Headers { get; set; }
    public int ExpectedStatus { get; set; }
    public bool ShouldBlock { get; set; }
}

public class TestResult
{
    public string TestName { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public bool Passed { get; set; }
    public string Message { get; set; } = string.Empty;
    public int ExpectedStatus { get; set; }
    public int ActualStatus { get; set; }
    public bool ShouldBlock { get; set; }
    public string? ResponseContent { get; set; }
    public int ExecutionTimeMs { get; set; }
}

public class TestSuiteSummary
{
    public int TotalTests { get; set; }
    public int PassedTests { get; set; }
    public int FailedTests { get; set; }
    public int ExecutionTime { get; set; }
    public List<TestResult> Results { get; set; } = new();
    public double SuccessRate => TotalTests > 0 ? (double)PassedTests / TotalTests * 100 : 0;
}
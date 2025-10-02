using Microsoft.Extensions.Options;
using ModSecPoc.ModSecurity.Configuration;
using System.Text;

namespace ModSecPoc.ModSecurity.Middleware;

/// <summary>
/// ASP.NET Core middleware for ModSecurity integration
/// </summary>
public class ModSecurityMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ModSecurityOptions _options;
    private readonly ILogger<ModSecurityMiddleware> _logger;
    private readonly ModSecurityEngine? _engine;
    private readonly ModSecurityRuleSet? _ruleSet;

    public ModSecurityMiddleware(
        RequestDelegate next,
        IOptions<ModSecurityOptions> options,
        ILogger<ModSecurityMiddleware> logger)
    {
        _next = next;
        _options = options.Value;
        _logger = logger;

        if (_options.Enabled)
        {
            try
            {
                _engine = new ModSecurityEngine();
                _ruleSet = _engine.CreateRuleSet();

                // Load primary rules file
                if (!string.IsNullOrEmpty(_options.RulesFile) && File.Exists(_options.RulesFile))
                {
                    _ruleSet.LoadRulesFromFile(_options.RulesFile);
                    _logger.LogInformation("Loaded ModSecurity rules from: {RulesFile}", _options.RulesFile);
                }

                // Load additional rules files
                foreach (var additionalRulesFile in _options.AdditionalRulesFiles)
                {
                    if (File.Exists(additionalRulesFile))
                    {
                        _ruleSet.LoadRulesFromFile(additionalRulesFile);
                        _logger.LogInformation("Loaded additional ModSecurity rules from: {RulesFile}", additionalRulesFile);
                    }
                    else
                    {
                        _logger.LogWarning("Additional rules file not found: {RulesFile}", additionalRulesFile);
                    }
                }

                _logger.LogInformation("ModSecurity engine initialized: {EngineInfo}", _engine.WhoAmI());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to initialize ModSecurity engine");
                throw;
            }
        }
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (!_options.Enabled)
        {
            await _next(context);
            return;
        }

        using var transaction = _engine.CreateTransaction(_ruleSet);
        
        try
        {
            // Process connection information
            var clientIp = context.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";
            var clientPort = context.Connection.RemotePort;
            var serverIp = context.Connection.LocalIpAddress?.ToString() ?? "127.0.0.1";
            var serverPort = context.Connection.LocalPort;

            transaction.ProcessConnection(clientIp, clientPort, serverIp, serverPort);

            // Process URI information
            var uri = context.Request.Path + context.Request.QueryString;
            var method = context.Request.Method;
            var httpVersion = context.Request.Protocol;

            _logger.LogInformation("Processing URI: {Uri}, Method: {Method}, QueryString: {QueryString}", 
                uri, method, context.Request.QueryString.ToString());

            transaction.ProcessUri(uri, method, httpVersion);

            // Add request headers
            foreach (var header in context.Request.Headers)
            {
                transaction.AddRequestHeader(header.Key, string.Join(", ", header.Value));
            }

            // Process request headers
            var requestHeadersResult = transaction.ProcessRequestHeaders();
            
            // Check for intervention after processing request headers
            var intervention = transaction.GetIntervention();
            _logger.LogInformation("Intervention after request headers: {HasIntervention}, IsDisruptive: {IsDisruptive}, EnforceMode: {EnforceMode}, Status: {Status}", 
                intervention != null, intervention?.IsDisruptive ?? false, _options.EnforceMode, intervention?.Status ?? 0);
            
            if (intervention != null && intervention.IsDisruptive && _options.EnforceMode)
            {
                _logger.LogWarning("Blocking request due to intervention: Status={Status}, Log={Log}", intervention.Status, intervention.Log);
                await HandleIntervention(context, intervention);
                return;
            }

            // Process request body if present
            if (context.Request.ContentLength > 0 && context.Request.ContentLength <= _options.MaxRequestBodySize)
            {
                context.Request.EnableBuffering();
                var requestBody = await ReadRequestBodyAsync(context.Request);
                if (requestBody.Length > 0)
                {
                    transaction.AppendRequestBody(requestBody);
                }
                
                var requestBodyResult = transaction.ProcessRequestBody();
                
                // Check for intervention after processing request body
                intervention = transaction.GetIntervention();
                _logger.LogInformation("Intervention after request body: {HasIntervention}, IsDisruptive: {IsDisruptive}, EnforceMode: {EnforceMode}", 
                    intervention != null, intervention?.IsDisruptive ?? false, _options.EnforceMode);
                
                if (intervention != null && intervention.IsDisruptive && _options.EnforceMode)
                {
                    _logger.LogWarning("Blocking request due to intervention: Status={Status}, Log={Log}", intervention.Status, intervention.Log);
                    await HandleIntervention(context, intervention);
                    return;
                }
                
                // Reset request body position for downstream middleware
                context.Request.Body.Position = 0;
            }

            // Continue to next middleware and capture response
            var originalBodyStream = context.Response.Body;
            using var responseBodyStream = new MemoryStream();
            context.Response.Body = responseBodyStream;

            await _next(context);

            // Process response
            await ProcessResponse(context, transaction, responseBodyStream, originalBodyStream);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing request through ModSecurity");
            await _next(context);
        }
    }

    private async Task ProcessResponse(HttpContext context, ModSecurityTransaction transaction, 
        MemoryStream responseBodyStream, Stream originalBodyStream)
    {
        // Add response headers
        foreach (var header in context.Response.Headers)
        {
            transaction.AddResponseHeader(header.Key, string.Join(", ", header.Value));
        }

        // Process response headers
        transaction.ProcessResponseHeaders(context.Response.StatusCode, context.Request.Protocol);

        // Process response body if present and within size limit
        responseBodyStream.Position = 0;
        if (responseBodyStream.Length > 0 && responseBodyStream.Length <= _options.MaxResponseBodySize)
        {
            var responseBody = responseBodyStream.ToArray();
            transaction.AppendResponseBody(responseBody);
        }

        var responseBodyResult = transaction.ProcessResponseBody();

        // Check for final intervention
        var intervention = transaction.GetIntervention();
        if (intervention != null)
        {
            _logger.LogWarning("ModSecurity intervention: Status={Status}, Log={Log}, Disruptive={IsDisruptive}",
                intervention.Status, intervention.Log, intervention.IsDisruptive);

            if (intervention.IsDisruptive && _options.EnforceMode)
            {
                // Clear the response and send intervention response
                context.Response.Clear();
                await HandleIntervention(context, intervention);
                return;
            }
        }

        // Copy response back to original stream
        responseBodyStream.Position = 0;
        await responseBodyStream.CopyToAsync(originalBodyStream);
    }

    private async Task<byte[]> ReadRequestBodyAsync(HttpRequest request)
    {
        using var reader = new StreamReader(request.Body, leaveOpen: true);
        var bodyContent = await reader.ReadToEndAsync();
        request.Body.Position = 0;
        return Encoding.UTF8.GetBytes(bodyContent);
    }

    private async Task HandleIntervention(HttpContext context, ModSecurityInterventionResult intervention)
    {
        context.Response.StatusCode = intervention.Status > 0 ? intervention.Status : _options.BlockStatusCode;
        context.Response.ContentType = "text/plain";

        var message = !string.IsNullOrEmpty(intervention.Log) ? intervention.Log : _options.BlockMessage;
        await context.Response.WriteAsync(message);

        _logger.LogWarning("Blocked request due to ModSecurity rule. Status: {Status}, Message: {Message}",
            context.Response.StatusCode, message);
    }
}
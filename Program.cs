using ModSecPoc.ModSecurity.Extensions;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Add ModSecurity services
builder.Services.AddModSecurity(builder.Configuration);

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// Add static files support
app.UseStaticFiles();

// Add ModSecurity middleware (should be early in the pipeline)
app.UseModSecurity();

// Add controller support
app.MapControllers();

var summaries = new[]
{
    "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
};

app.MapGet("/weatherforecast", () =>
{
    var forecast =  Enumerable.Range(1, 5).Select(index =>
        new WeatherForecast
        (
            DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            Random.Shared.Next(-20, 55),
            summaries[Random.Shared.Next(summaries.Length)]
        ))
        .ToArray();
    return forecast;
})
.WithName("GetWeatherForecast")
.WithOpenApi();

// Test endpoints for ModSecurity validation
app.MapGet("/test/modsecurity", () =>
{
    return Results.Ok(new { message = "ModSecurity test endpoint", status = "protected" });
})
.WithName("TestModSecurity")
.WithOpenApi();

app.MapPost("/test/sqli", (TestRequest request) =>
{
    // This endpoint will be protected by ModSecurity against SQL injection
    return Results.Ok(new { message = "Data processed successfully", input = request.Data });
})
.WithName("TestSQLInjection")
.WithOpenApi();

app.MapPost("/test/xss", (TestRequest request) =>
{
    // This endpoint will be protected by ModSecurity against XSS
    return Results.Ok(new { message = "Content processed successfully", content = request.Data });
})
.WithName("TestXSS")
.WithOpenApi();

app.MapGet("/test/traversal", (string? path) =>
{
    // This endpoint will be protected by ModSecurity against directory traversal
    return Results.Ok(new { message = "Path processed successfully", requestedPath = path });
})
.WithName("TestDirectoryTraversal")
.WithOpenApi();

// Test suite interface
app.MapGet("/test-suite", () =>
{
    return Results.Redirect("/test-suite.html");
})
.WithName("TestSuite")
.WithOpenApi();

app.Run();

record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}

record TestRequest(string Data);

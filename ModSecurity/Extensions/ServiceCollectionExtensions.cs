using Microsoft.Extensions.DependencyInjection;
using ModSecPoc.ModSecurity.Configuration;
using ModSecPoc.ModSecurity.Middleware;

namespace ModSecPoc.ModSecurity.Extensions;

/// <summary>
/// Extension methods for registering ModSecurity services
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Add ModSecurity services to the service collection
    /// </summary>
    public static IServiceCollection AddModSecurity(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<ModSecurityOptions>(configuration.GetSection(ModSecurityOptions.SectionName));
        return services;
    }

    /// <summary>
    /// Add ModSecurity services to the service collection with configuration action
    /// </summary>
    public static IServiceCollection AddModSecurity(this IServiceCollection services, Action<ModSecurityOptions> configure)
    {
        services.Configure(configure);
        return services;
    }
}

/// <summary>
/// Extension methods for configuring ModSecurity middleware
/// </summary>
public static class ApplicationBuilderExtensions
{
    /// <summary>
    /// Use ModSecurity middleware in the request pipeline
    /// </summary>
    public static IApplicationBuilder UseModSecurity(this IApplicationBuilder app)
    {
        return app.UseMiddleware<ModSecurityMiddleware>();
    }
}
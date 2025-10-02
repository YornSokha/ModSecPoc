#!/bin/bash

echo "=== Running ModSecPoc in Debug Mode ==="
echo ""

# Build in debug mode
echo "Building in debug configuration..."
dotnet build --configuration Debug

echo ""
echo "Starting application in debug mode..."
echo "- Environment: Development"
echo "- URL: http://localhost:5000"
echo "- Debug symbols: Enabled"
echo "- Verbose logging: Enabled"
echo ""

# Set debug environment variables
export ASPNETCORE_ENVIRONMENT=Development
export ASPNETCORE_URLS=http://localhost:5000
export Logging__LogLevel__Default=Debug
export Logging__LogLevel__ModSecPoc.ModSecurity=Debug

# Run with debug configuration
dotnet run --configuration Debug --verbosity normal
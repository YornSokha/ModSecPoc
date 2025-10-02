#!/bin/bash

echo "=== ModSecPoc with Enhanced ModSecurity Debug Logging ==="
echo ""

# Create debug modsecurity configuration
cat > modsecurity/debug.conf << 'EOF'
# Debug configuration for ModSecurity
SecDebugLog /tmp/modsec_debug.log
SecDebugLogLevel 9

# Audit logging for detailed request/response analysis
SecAuditEngine On
SecAuditLogType Serial
SecAuditLog /tmp/modsec_audit.log
SecAuditLogParts ABIJDEFHZ

# Rule matching details
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess On
EOF

echo "Created enhanced debug configuration:"
echo "- ModSecurity debug log: /tmp/modsec_debug.log (level 9 - most verbose)"
echo "- ModSecurity audit log: /tmp/modsec_audit.log"
echo ""

# Set environment for maximum debugging
export ASPNETCORE_ENVIRONMENT=Development
export ASPNETCORE_URLS=http://localhost:5000
export Logging__LogLevel__Default=Debug
export Logging__LogLevel__ModSecPoc=Trace
export Logging__LogLevel__Microsoft.AspNetCore=Information

echo "Environment configured for debug mode"
echo "Starting application..."
echo ""
echo "📝 Monitor logs in real-time:"
echo "   tail -f /tmp/modsec_debug.log"
echo "   tail -f /tmp/modsec_audit.log"
echo ""

dotnet run --configuration Debug